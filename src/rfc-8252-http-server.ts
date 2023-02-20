import { createServer as createHTTPServer } from 'http';
import type { Server as HTTPServer } from 'http';
import type { LookupAddress } from 'dns';
import { promises as dns, ADDRCONFIG } from 'dns';
import { EventEmitter, once } from 'events';
import type { RequestHandler } from 'express';
import express from 'express';
import { promisify } from 'util';
import { randomBytes } from 'crypto';
import type {
  MongoDBOIDCLogEventsMap,
  OIDCAbortSignal,
  TypedEventEmitter,
} from './types';
import { MongoDBOIDCError } from './types';
import { withAbortCheck } from './util';
import type { AddressInfo } from 'net';

// For starting the HTTP server, we'll need the path at which
// we receive OAuth tokens.
export interface RFC8252HTTPServerOptions {
  redirectUrl: string;
  logger?: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
}

/** @internal */
export class RFC8252HTTPServer {
  private readonly redirectUrl: URL;
  private readonly logger: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
  private servers: HTTPServer[] = [];
  private readonly expressApp: ReturnType<typeof express>;
  private readonly redirects = new Map<
    string,
    { targetUrl: string; onAccessed: () => void }
  >();
  private readonly oidcParamsPromise: Promise<string>;
  private oidcParamsResolve?: (params: string) => void;

  constructor(options: RFC8252HTTPServerOptions) {
    this.redirectUrl = new URL(options.redirectUrl);
    this.logger = options.logger ?? new EventEmitter();
    this.oidcParamsPromise = new Promise<string>(
      (resolve) => (this.oidcParamsResolve = resolve)
    );

    this.expressApp = express();
    // Identity providers are not strictly required to use the query string to
    // pass tokens and can also use the body as a form POST, even though the
    // former is the common mechanism.
    // This makes it a lot more convenient to use a HTTP framework like
    // express here, which handles cases that require POST body parsing for us.
    this.expressApp.use(express.urlencoded({ extended: false }));
    this.expressApp.use(express.json());

    // Redirect to external server:
    this.expressApp.get('/redirect/:id', this._handleRedirectToExternal);
    // Redirect from external server:
    this.expressApp.all(this.redirectUrl.pathname, this._handleOIDCCallback);
    // Everything else:
    this.expressApp.all('*', this._fallbackHandler);
  }

  private _handleRedirectToExternal: RequestHandler<{ id: string }> = (
    req,
    res,
    next
  ) => {
    const entry = this.redirects.get(req.params.id);
    if (!entry) return next();

    this.logger.emit('mongodb-oidc-plugin:local-redirect-accessed', {
      id: req.params.id,
    });
    // This can be helpful for figuring out whether a browser was
    // opened successfully.
    entry.onAccessed();
    res.status(307);
    res.set('Location', entry.targetUrl);
    res.send();
  };

  private _handleOIDCCallback: RequestHandler = (req, res) => {
    const baseUrl = this.listeningRedirectUrl;
    if (!baseUrl) {
      throw new MongoDBOIDCError('Received HTTP request while not listening');
    }
    const url = new URL(req.url, baseUrl);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    const hasBody = Object.keys(req.body || {}).length > 0;
    if (req.method === 'POST' && hasBody) {
      // Convert the POST body to a querystring.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      url.search = new URLSearchParams(Object.entries(req.body)).toString();
    } else if (req.method !== 'GET') {
      this.logger.emit('mongodb-oidc-plugin:oidc-callback-rejected', {
        method: req.method,
        hasBody,
      });
      res.status(405);
      res.type('text/plain');
      res.send('405 Invalid Method');
      return;
    }
    this.logger.emit('mongodb-oidc-plugin:oidc-callback-accepted', {
      method: req.method,
      hasBody,
    });
    res.status(200);
    res.type('text/plain');
    res.send('Welcome! Everything is fine.');
    this.oidcParamsResolve?.(url.toString());
  };

  private _fallbackHandler: RequestHandler = (req, res) => {
    this.logger.emit('mongodb-oidc-plugin:unknown-url-accessed', {
      method: req.method,
      path: req.url,
    });
    // TODO(MONGOSH-1396): Here and elsewhere, we should allow callers of the
    // library to specify custom pages instead of these text/plain shorthands.
    res.status(404);
    res.type('text/plain');
    res.send('404 Not Found');
  };

  /**
   * Add a redirect from a local URL served on the server to an external URL.
   */
  public async addRedirect(targetUrl: string): Promise<{
    localUrl: string;
    onAccessed: Promise<void>;
  }> {
    const baseUrl = this.listeningRedirectUrl;
    if (!baseUrl) {
      throw new Error('Cannot add redirect URL before server is listening');
    }
    const hash = (await promisify(randomBytes)(16)).toString('hex');
    const onAccessed = new Promise<void>((resolve) => {
      this.redirects.set(hash, { targetUrl, onAccessed: resolve });
    });
    const localUrl = new URL('/redirect/' + hash, baseUrl).toString();
    return {
      localUrl,
      onAccessed,
    };
  }

  /**
   * Returns the port that this server is listening on if
   * listen() was successfully called and undefined otherwise.
   */
  public get listeningPort(): number | undefined {
    if (this.servers.length === 0) return undefined;
    const ports = new Set(
      this.servers.map((srv) => (srv.address() as AddressInfo)?.port)
    );
    const port = ports.size === 1 && [...ports][0];
    if (typeof port !== 'number') {
      // Should never happen
      throw new MongoDBOIDCError(
        `Server is listening in inconsistent state: ${[...ports].join(',')}`
      );
    }
    return port;
  }

  /**
   * Returns the full redirectURL passed to the constructor, with
   * a possible unspecified port resolved to the actual port,
   * or undefined if this server is not listening.
   */
  public get listeningRedirectUrl(): string | undefined {
    const port = this.listeningPort;
    if (!port) return undefined;
    const url = new URL(this.redirectUrl.toString());
    url.port = String(port);
    return url.toString();
  }

  /**
   * Create HTTP servers and listen on them corresponding to the redirect URL
   * provided to the constructor.
   */
  public async listen(): Promise<void> {
    if (this.listeningPort !== undefined) {
      throw new MongoDBOIDCError(
        `Already listening on ${this.redirectUrl.toString()}`
      );
    }

    if (this.redirectUrl.protocol !== 'http:') {
      throw new MongoDBOIDCError(
        `Cannot handle listening on non-HTTP URL, got ${this.redirectUrl.protocol}`
      );
    }

    this.logger.emit('mongodb-oidc-plugin:local-listen-started', {
      url: this.redirectUrl.toString(),
    });

    // https://www.rfc-editor.org/rfc/rfc8252#section-7.3 states:
    // > It is RECOMMENDED that clients attempt to bind to the loopback
    // > interface using both IPv4 and IPv6 and use whichever is available.
    // Practically speaking, `hostname` here is almost always going to
    // be 'localhost'. Doing a dns lookup with ADDRCONFIG is the easiest
    // way to get IPv4 and IPv6 addresses and whichever else 'localhost'
    // resolves to while taking into account their respective availability
    // on the current host. While we could theoretically hardcode 'localhost'
    // here, there doesn't seem to be any reason to do so, and doing so
    // would remove the ability to configure IPv4 or IPv6 explicitly
    // (by specifying 127.0.0.1/::1 as hosts). Finally, we also don't want
    // to do what Node.js does by default when only a host is provided,
    // namely listening on all interfaces.
    let hostname = this.redirectUrl.hostname;
    if (hostname.startsWith('[') && hostname.endsWith(']'))
      hostname = hostname.slice(1, -1);
    const dnsResults = await dns.lookup(hostname, {
      all: true,
      hints: ADDRCONFIG,
    });

    if (dnsResults.length === 0) {
      throw new MongoDBOIDCError(
        `DNS query for ${this.redirectUrl.hostname} returned no results`
      );
    }

    try {
      const urlPort =
        this.redirectUrl.port === '' ? 80 : +this.redirectUrl.port;

      // Two scenarios: Either we are listening on an arbitrary port here,
      // or listening on a specific port. Using an arbitrary port has the
      // advantage that the OS will allocate a free one for us, while a
      // specific port may or may not be available.
      // If we listen on an arbitrary port and the URL hostname resolved
      // to multiple distinct addresses, we need to listen to the same port
      // on all of these addresses. This is extremely unlikely to be an issue
      // in practice, but nevertheless something that should be handled.
      // (We cannot just listen on one address and let a program that happens
      // to listen on the same port on another address receive our secret
      // OIDC tokens...)
      // We handle that case by first listening one on address, receiving the
      // port there, and then trying to listen on all other addresses on the
      // same port. We repeat this as necessary.
      const kMaxAttempts = urlPort === 0 ? 10 : 1;
      for (let attempts = 1; ; attempts++) {
        let port = urlPort;
        let offset = 0;
        if (urlPort === 0) {
          offset = 1;
          // Listen on an arbitrary port on a single interface first...
          const firstServer = this.createServerAndListen(dnsResults[0], 0);
          this.servers = [firstServer];
          await once(firstServer, 'listening');
          port = (firstServer.address() as AddressInfo)?.port;
          if (typeof port !== 'number') {
            // Should never happen
            throw new MongoDBOIDCError(
              `Listening on ${dnsResults[0].address} did not return a port`
            );
          }
        }
        try {
          // ... and then listen on all remaining interfaces on the same port.
          const otherServers = dnsResults
            .slice(offset)
            .map((dnsResult) => this.createServerAndListen(dnsResult, port));
          this.servers.push(...otherServers);
          await Promise.all(
            otherServers.map((server) => once(server, 'listening'))
          );
          break;
        } catch (err: unknown) {
          await this.close();
          if (attempts === kMaxAttempts) throw err;
        }
      }
    } catch (err: unknown) {
      await this.close();
      this.logger.emit('mongodb-oidc-plugin:local-listen-failed', {
        url: this.redirectUrl.toString(),
      });
      throw err;
    }

    this.logger.emit('mongodb-oidc-plugin:local-listen-succeeded', {
      url: this.listeningRedirectUrl || '',
      interfaces: dnsResults.map((dnsResult) => dnsResult.address),
    });
  }

  private createServerAndListen(
    dnsResult: LookupAddress,
    port: number
  ): HTTPServer {
    const { address: host, family } = dnsResult;
    const server = createHTTPServer((req, res) => this.expressApp(req, res));
    server.listen({
      host,
      port,
      // This code isn't really expected to run inside a Node.js cluster
      // fork, but if it does, we should not allow external handlers.
      exclusive: true,
      // Should not be making a difference in practice since `host` is
      // almost never the listen-on-all IPv6 address (`::`), but if it is,
      // this is the correct thing to do.
      ipv6Only: family === 6 ? true : undefined,
    });
    return server;
  }

  /**
   * Returns the OIDC params as the full URL used to access them
   * (regardless of whether OIDC params were passed as URL params or not)
   */
  public async waitForOIDCParams(): Promise<string> {
    return await this.oidcParamsPromise;
  }

  /**
   * Close all resources associated with this server.
   */
  public async close(): Promise<void> {
    this.logger.emit('mongodb-oidc-plugin:local-server-close', {
      url: this.redirectUrl.toString(),
    });
    const servers = this.servers;
    this.servers = [];
    await Promise.all(
      servers.map(async (server) => {
        server.close();
        await once(server, 'close');
      })
    );
  }

  /**
   * Convenience method to wait until a single successful OIDC parameter
   * request is received or abort early, and close the server in any case.
   */
  public async waitForOIDCParamsAndClose({
    signal,
  }: {
    signal?: OIDCAbortSignal;
  } = {}): Promise<string> {
    try {
      return await withAbortCheck(signal, async ({ signalPromise }) => {
        return await Promise.race([this.waitForOIDCParams(), signalPromise]);
      });
    } finally {
      await this.close();
    }
  }
}
