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
import type { AddressInfo, Socket } from 'net';
import type {
  RedirectServerRequestHandler,
  RedirectServerRequestInfo,
} from './api';

// For starting the HTTP server, we'll need the path at which
// we receive OAuth tokens.
export interface RFC8252HTTPServerOptions {
  redirectUrl: string;
  oidcStateParam: string;
  logger?: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
  redirectServerRequestHandler?: RedirectServerRequestHandler;
}

/** @internal */
export class RFC8252HTTPServer {
  private readonly redirectUrl: URL;
  private readonly oidcStateParam: string;
  private readonly redirectServerHandler: RedirectServerRequestHandler;
  private readonly logger: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
  private servers: HTTPServer[] = [];
  private clientConnections: Socket[] = [];
  private readonly expressApp: ReturnType<typeof express>;
  private readonly redirects = new Map<
    string,
    { targetUrl: string; onAccessed: () => void }
  >();

  // Promise that is resolved with the OIDC params once the user is
  // done navigating to the success page.
  private readonly oidcParamsPromise: Promise<string>;
  private oidcParamsResolve?: (params: string) => void;
  private oidcParamsReject?: (error: MongoDBOIDCError) => void;
  // Place to temporarily store params between accepting the redirect
  // and the user accessing the success page.
  private oidcParams: string | undefined;

  constructor(options: RFC8252HTTPServerOptions) {
    this.redirectUrl = new URL(options.redirectUrl);
    this.oidcStateParam = options.oidcStateParam;
    this.redirectServerHandler =
      options.redirectServerRequestHandler ?? defaultRedirectServerHandler;
    this.logger = options.logger ?? new EventEmitter();
    this.oidcParamsPromise = new Promise<string>(
      (resolve, reject) =>
        ([this.oidcParamsResolve, this.oidcParamsReject] = [resolve, reject])
    );
    // Errors are handled by the caller of this instance.
    this.oidcParamsPromise.catch(() => {
      /* Suppress UnhandledPromiseRejectionWarning */
    });

    this.expressApp = express();
    // Identity providers are not strictly required to use the query string to
    // pass tokens and can also use the body as a form POST, even though the
    // former is the common mechanism.
    // This makes it a lot more convenient to use a HTTP framework like
    // express here, which handles cases that require POST body parsing for us.
    this.expressApp.use(express.urlencoded({ extended: false }));
    this.expressApp.use(express.json());
    this.expressApp.use((req, res, next) => {
      // Set some default HTTP security headers. The CSP here is fairly strict,
      // but specific handlers can override these as necessary.
      res.setHeader('Content-Security-Policy', "default-src 'self'");
      res.setHeader('Referrer-Policy', 'no-referrer');
      next();
    });

    // Redirect to external server:
    this.expressApp.get('/redirect/:id', this._handleRedirectToExternal);
    // Redirect from external server:
    this.expressApp.all(this.redirectUrl.pathname, this._handleOIDCCallback);
    // Success page:
    this.expressApp.get('/success/:nonce', this._handleSuccess);
    // Everything else:
    this.expressApp.all('*', this._fallbackHandler);
  }

  private _handleSuccess: RequestHandler = (req, res, next) => {
    const { oidcParams } = this;
    if (!oidcParams) {
      return next();
    }
    this.redirectServerHandler({
      req,
      res,
      result: 'accepted',
      status: 200,
    });
    res.on('finish', () => {
      this.oidcParamsResolve?.(oidcParams);
    });
  };

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
    this.redirectServerHandler({
      req,
      res,
      status: 307,
      result: 'redirecting',
      location: entry.targetUrl,
    });
  };

  private _handleOIDCCallback: RequestHandler = (req, res) => {
    const baseUrl = this.listeningRedirectUrl;
    if (!baseUrl) {
      throw new MongoDBOIDCError('Received HTTP request while not listening');
    }

    let isAcceptedOIDCResponse = false;
    const reject = (
      info: Omit<
        RedirectServerRequestInfo & { result: 'rejected' },
        'req' | 'res' | 'result'
      >
    ) => {
      this.logger.emit('mongodb-oidc-plugin:oidc-callback-rejected', {
        method: req.method,
        hasBody,
        errorCode: info.error ?? 'unknown_error',
        isAcceptedOIDCResponse,
      });

      this.redirectServerHandler({
        req,
        res,
        result: 'rejected',
        ...info,
      });

      if (isAcceptedOIDCResponse) {
        this.oidcParamsReject?.(
          new MongoDBOIDCError(
            `${info.error || 'unknown_code'}: ${
              info.errorDescription || '[no details]'
            }`
          )
        );
      }
    };

    const url = new URL(req.url, baseUrl);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    const hasBody = Object.keys(req.body || {}).length > 0;
    if (req.method === 'POST' && hasBody) {
      // Convert the POST body to a querystring.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      url.search = new URLSearchParams(Object.entries(req.body)).toString();
    } else if (req.method !== 'GET') {
      reject({
        status: 405,
        error: 'invalid_method',
        errorDescription: 'Invalid HTTP Method',
      });
      return;
    }

    // If `state` does not match the expected value, this might be a CSRF request.
    // Even if we did progress from here, the OIDC library would reject this
    // request, but bailing out early here means that after this conditional
    // we know we are dealing with a genuine response from the auth server and
    // can reject the `oidcParamsPromise` if there is an error.
    if (url.searchParams.get('state') !== this.oidcStateParam) {
      reject({
        status: 403,
        error: 'state_mismatch',
        errorDescription: '',
      });
      return;
    }
    isAcceptedOIDCResponse = true;

    const oidcParams = url.toString();
    if (this.oidcParams !== undefined && this.oidcParams !== oidcParams) {
      // This should not happen in practice...
      reject({
        status: 409,
        error: 'already_received_code',
        errorDescription:
          'A different authentication code was already received by the application',
      });
      return;
    }
    this.oidcParams = oidcParams;
    this.logger.emit('mongodb-oidc-plugin:oidc-callback-accepted', {
      method: req.method,
      hasBody,
      errorCode: url.searchParams.get('error') ?? undefined,
    });

    if (url.searchParams.get('error')) {
      reject({
        status: 200,
        // Standard params from https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
        error:
          ensureNQSChar(url.searchParams.get('error')) ?? 'invalid_error_param',
        errorDescription: ensureNQSChar(
          url.searchParams.get('error_description')
        ),
        errorURI: ensureURI(url.searchParams.get('error_uri')),
      });
      return;
    }

    // https://mailarchive.ietf.org/arch/msg/oauth/RqlUvseG_RnOWrEV_WJACW8oUdU/
    // > Callback URL pages SHOULD redirect to a trusted page immediately after
    // > receiving the authorization code in the URL.  This prevents the
    // > authorization code from remaining in the browser history, or from
    // > inadvertently leaking in a referer header.
    void (async () => {
      // `nonce` does not have any special security properties here, it is only
      // there to avoid collisions with a redirect_url that happens to start
      // with `/success`
      const nonce = (await promisify(randomBytes)(16)).toString('hex');
      res.status(303); // 'See Other', turns a potential POST into GET
      res.set('Location', `/success/${nonce}`);
      res.send();
    })();
  };

  private _fallbackHandler: RequestHandler = (req, res) => {
    this.logger.emit('mongodb-oidc-plugin:unknown-url-accessed', {
      method: req.method,
      path: req.url,
    });

    this.redirectServerHandler({
      req,
      res,
      result: 'unknown-url',
      status: 404,
    });
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
    server.on('connection', (socket) => {
      this.clientConnections.push(socket);
      socket.on('close', () => {
        const index = this.clientConnections.indexOf(socket);
        if (index !== -1) this.clientConnections.splice(index, 1);
      });
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
    // Node.js servers emit 'close' events in response to .close(),
    // but we are not waiting for that here, because:
    // - Those events are not actually correlated to the server closing, Node.js
    //   just closes the underlying handle and ignores that that is an async operation
    //   (https://github.com/nodejs/node/blob/38b82b0604d6515b281c6586d6999d2c67248e7f/lib/net.js#L2178)
    // - Node.js does, however, wait for all incoming connections to be closed
    //   before emitting the event. That can be convenient sometimes, but browsers
    //   can keep idle connections open for a while as a sort of 'connection cache',
    //   so waiting for the 'close' event would potentially delay this event indefinitely.
    for (const server of this.servers) server.close();
    this.servers = [];
    for (const socket of this.clientConnections) {
      // Close the open sockets. Not much point in waiting for a 'close'
      // event here.
      socket.on('error', () => {
        /* ignore */
      });
      socket.destroy();
    }
    this.clientConnections = [];
    return Promise.resolve(); // Keeping this async in case we ever need it to be.
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

function defaultRedirectServerHandler(info: RedirectServerRequestInfo): void {
  const { res, result, status } = info;
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/plain');
  switch (result) {
    case 'redirecting':
      res.setHeader('Location', info.location);
      res.end('Redirecting...');
      return;
    case 'accepted':
      res.end('Authentication successful! You can close this window now.');
      return;
    case 'rejected': {
      const { error, errorDescription, errorURI } = info;
      let text = 'Authentication failed!\n';
      if (error) text += `Error: ${error}\n`;
      if (errorDescription) text += `Details: ${errorDescription}\n`;
      if (errorURI) text += `More information: ${errorURI}\n`;
      res.end(text);
      return;
    }
    case 'unknown-url':
      res.end('Not found');
      return;
  }
}

// Ensure that `str` confirms to the `NQSCHAR` definition used in RFC6749 (OAuth 2.0)
// and return `undefined` if it is empty or non-conforming.
// (This deviates from the spec slightly in that it allows characters outside of ASCII).
function ensureNQSChar(str: string | undefined | null): string | undefined {
  // eslint-disable-next-line no-control-regex
  if (!str || /[\x00-\x1f\x22\x5c\x7f]/.test(str)) return undefined;
  return str;
}

function ensureURI(str: string | undefined | null): string | undefined {
  if (!str) return undefined;
  try {
    new URL(str);
    return str;
  } catch {
    return undefined;
  }
}
