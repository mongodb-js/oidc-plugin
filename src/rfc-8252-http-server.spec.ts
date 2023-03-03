import { RFC8252HTTPServer } from './rfc-8252-http-server';
import { expect } from 'chai';
import type { Server as HTTPServer } from 'http';
import { createServer as createHTTPServer } from 'http';
import { EventEmitter, once } from 'events';
import type { AddressInfo } from 'net';
import type { SinonSandbox } from 'sinon';
import sinon from 'sinon';
import { AbortController } from './util';
import { promisify } from 'util';
import { randomBytes } from 'crypto';

// node-fetch@3 is ESM-only...
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
const fetch: typeof import('node-fetch').default = (...args) =>
  eval("import('node-fetch')").then(({ default: fetch }) => fetch(...args));

describe('RFC8252HTTPServer', function () {
  let server: RFC8252HTTPServer;
  let externalServer: HTTPServer;
  let externalServerPort: number;
  let logger: EventEmitter;
  let events: [string, ...unknown[]][];
  let sandbox: SinonSandbox;
  let oidcStateParam: string;

  before(async function () {
    externalServer = createHTTPServer((req, res) => {
      res.end(JSON.stringify({ url: req.url }));
    });
    externalServer.listen(0, '127.0.0.1');
    await once(externalServer, 'listening');
    externalServerPort = (externalServer.address() as AddressInfo).port;
    oidcStateParam = (await promisify(randomBytes)(16)).toString('hex');
  });
  after(async function () {
    externalServer.close();
    await once(externalServer, 'close');
  });

  beforeEach(function () {
    sandbox = sinon.createSandbox();
    events = [];
    logger = new EventEmitter();
    const origEmit = logger.emit.bind(logger);
    sinon.replace(logger, 'emit', function (event: string, ...args: any[]) {
      events.push([event, ...args]);
      return origEmit.call(this, args);
    });
  });

  afterEach(async function () {
    await server?.close();
    sandbox.restore();
  });

  context('with a specific port', function () {
    it('can listen localhost and handle requests', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://localhost:27097/oidc%20redirect',
        logger,
        oidcStateParam,
      });
      expect(server.listeningPort).to.equal(undefined);
      await server.listen();
      expect(server.listeningPort).to.equal(27097);

      const url = `http://localhost:27097/oidc%20redirect?foo=bar&state=${oidcStateParam}`;
      const res = await fetch(url);
      expect(res.status).to.equal(200);
      expect(await server.waitForOIDCParams()).to.equal(url);

      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:local-listen-started'
      );
      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:local-listen-succeeded'
      );
      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:oidc-callback-accepted'
      );
    });
  });

  context('with an IPv4-only redirect URL', function () {
    it('can listen on 127.0.0.1 and handle requests', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://127.0.0.1:0/oidc%20redirect',
        logger,
        oidcStateParam,
      });
      expect(server.listeningPort).to.equal(undefined);
      await server.listen();
      expect(server.listeningPort).to.be.a('number');

      const url = new URL(server.listeningRedirectUrl || '');
      url.search = `foo=bar&state=${oidcStateParam}`;
      const res = await fetch(url.toString());
      expect(res.status).to.equal(200);
      expect(await server.waitForOIDCParams()).to.equal(url.toString());
    });

    it('rejects IPv6 connection attempts', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://127.0.0.1:0/oidc%20redirect',
        logger,
        oidcStateParam,
      });
      await server.listen();
      const url = new URL(server.listeningRedirectUrl || '');
      url.hostname = '[::1]';
      try {
        await fetch(url.toString());
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.include('ECONNREFUSED');
      }
    });
  });

  context('with an IPv6-only redirect URL', function () {
    it('can listen on ::1 and handle requests', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://[::1]:0/oidc%20redirect',
        logger,
        oidcStateParam,
      });
      expect(server.listeningPort).to.equal(undefined);
      await server.listen();
      expect(server.listeningPort).to.be.a('number');

      const url = new URL(server.listeningRedirectUrl || '');
      url.search = `foo=bar&state=${oidcStateParam}`;
      const res = await fetch(url.toString());
      expect(res.status).to.equal(200);
      expect(await server.waitForOIDCParams()).to.equal(url.toString());
    });

    it('rejects IPv4 connection attempts', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://[::1]:0/oidc%20redirect',
        logger,
        oidcStateParam,
      });
      await server.listen();
      const url = new URL(server.listeningRedirectUrl || '');
      url.hostname = '127.0.0.1';
      try {
        await fetch(url.toString());
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.include('ECONNREFUSED');
      }
    });
  });

  context('with an unresolvable URL', function () {
    it('fails to listen', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://doesnotexist/',
        logger,
        oidcStateParam,
      });
      try {
        await server.listen();
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.include('getaddrinfo');
      }
    });
  });

  context('when the port is already in use', function () {
    it('fails to listen', async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: `http://localhost:${externalServerPort}/`,
        logger,
        oidcStateParam,
      });
      try {
        await server.listen();
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.include('EADDRINUSE');
      }
    });
  });

  context('with an arbitrary port on localhost', function () {
    let url: URL;
    beforeEach(async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://localhost:0/oidc-redirect',
        logger,
        oidcStateParam,
      });
      expect(server.listeningPort).to.equal(undefined);
      await server.listen();
      expect(server.listeningPort).to.be.a('number');
      url = new URL(server.listeningRedirectUrl || '');
    });

    it('can accept urlencoded POST bodies', async function () {
      const params = new URLSearchParams([
        ['foo', 'bar'],
        ['baz', 'quux'],
        ['state', oidcStateParam],
      ]);
      const res = await fetch(url.toString(), {
        method: 'POST',
        body: params,
      });
      expect(res.status).to.equal(200);

      url.search = params.toString();
      expect(await server.waitForOIDCParams()).to.equal(url.toString());

      expect(events).to.deep.include([
        'mongodb-oidc-plugin:oidc-callback-accepted',
        { method: 'POST', hasBody: true, errorCode: undefined },
      ]);
    });

    it('can accept JSON POST bodies', async function () {
      const params = { foo: 'bar', baz: 'quux', state: oidcStateParam };
      const res = await fetch(url.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(params),
      });
      expect(res.status).to.equal(200);

      url.search = new URLSearchParams(Object.entries(params)).toString();
      expect(await server.waitForOIDCParams()).to.equal(url.toString());

      expect(events).to.deep.include([
        'mongodb-oidc-plugin:oidc-callback-accepted',
        { method: 'POST', hasBody: true, errorCode: undefined },
      ]);
    });

    it('rejects request other than POST or GET for the OIDC callback', async function () {
      const res = await fetch(url.toString(), {
        method: 'PUT',
        headers: { 'Content-Type': 'text/plain' },
        body: 'hello world',
      });
      expect(res.status).to.equal(405);
    });

    it('returns 404 for unknown endpoints', async function () {
      url.pathname = '/unknown';
      const res = await fetch(url.toString());
      expect(res.status).to.equal(404);
    });

    it('returns 404 for unknown redirect endpoints', async function () {
      url.pathname = '/redirect/asdf';
      const res = await fetch(url.toString());
      expect(res.status).to.equal(404);
    });

    it('allows setting up external redirects', async function () {
      const externalServerURL = `http://127.0.0.1:${externalServerPort}/test`;
      const result = await server.addRedirect(externalServerURL);
      const res = await fetch(result.localUrl);
      expect(res.status).to.equal(200);
      expect(await res.json()).to.deep.equal({ url: '/test' });

      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:local-redirect-accessed'
      );
    });

    it('rejects subsequent attempts at calling .listen()', async function () {
      try {
        await server.listen();
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.include('Already listening');
      }
    });

    it('can use the waitForOIDCParamsAndClose and receive tokens through it', async function () {
      const conveniencePromise = server.waitForOIDCParamsAndClose();
      const params = new URLSearchParams([
        ['foo', 'bar'],
        ['baz', 'quux'],
        ['state', oidcStateParam],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(res.status).to.equal(200);
      expect(await conveniencePromise).to.equal(url.toString());
      expect(server.listeningPort).to.equal(undefined);
    });

    it('can use the waitForOIDCParamsAndClose and abort early through it', async function () {
      const controller = new AbortController();
      const conveniencePromise = server.waitForOIDCParamsAndClose({
        signal: controller.signal,
      });
      setImmediate(() => controller.abort());
      try {
        await conveniencePromise;
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.match(/abort|cancel/i);
      }
      expect(server.listeningPort).to.equal(undefined);
    });

    it('rejects a missing state parameter with a 403 error', async function () {
      const params = new URLSearchParams([
        ['foo', 'bar'],
        ['baz', 'quux'],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(res.status).to.equal(403);
    });

    it('rejects an invalid state parameter with a 403 error', async function () {
      const params = new URLSearchParams([
        ['foo', 'bar'],
        ['baz', 'quux'],
        ['state', 'somevalue'],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(res.status).to.equal(403);
    });

    it('rejects the waitForOIDCParams promise when there is an OIDC error', async function () {
      const conveniencePromise = server.waitForOIDCParamsAndClose();
      conveniencePromise.catch(() => {
        /* squelch UnhandledPromiseRejectionWarning */
      });
      const params = new URLSearchParams([
        ['error', 'test_error'],
        ['state', oidcStateParam],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(res.status).to.equal(200);
      try {
        await conveniencePromise;
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.include('test_error');
      }
      expect(server.listeningPort).to.equal(undefined);
    });
  });

  context('with a custom HTTP handler', function () {
    let url: URL;
    beforeEach(async function () {
      server = new RFC8252HTTPServer({
        redirectUrl: 'http://localhost:0/oidc-redirect',
        logger,
        oidcStateParam,
        redirectServerRequestHandler(info) {
          const { res, req, status, ...extra } = info;
          res.statusCode = status;
          res.setHeader('Content-Type', 'text/json');
          res.end(JSON.stringify({ method: req.method, status, ...extra }));
        },
      });
      await server.listen();
      url = new URL(server.listeningRedirectUrl || '');
    });

    it('handles the success case', async function () {
      const params = new URLSearchParams([
        ['foo', 'bar'],
        ['baz', 'quux'],
        ['state', oidcStateParam],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(res.headers.get('Referrer-Policy')).to.equal('no-referrer');
      expect(res.headers.get('Content-Security-Policy')).to.equal(
        "default-src 'self'"
      );
      expect(res.url).to.include('/success/');
      expect(await res.json()).to.deep.equal({
        method: 'GET',
        status: 200,
        result: 'accepted',
      });
    });

    it('handles the error case', async function () {
      const params = new URLSearchParams([
        ['error', 'error'],
        ['error_description', 'error_description'],
        ['error_uri', 'http://error_uri'],
        ['state', oidcStateParam],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(await res.json()).to.deep.equal({
        method: 'GET',
        status: 200,
        result: 'rejected',
        error: 'error',
        errorDescription: 'error_description',
        errorURI: 'http://error_uri',
      });
    });

    it('does not pass along non-spec-compliant error information', async function () {
      const params = new URLSearchParams([
        ['error', 'er"ror'],
        ['error_description', 'error_"description'],
        ['error_uri', 'not_a_uri'],
        ['state', oidcStateParam],
      ]);
      url.search = params.toString();
      const res = await fetch(url.toString());
      expect(await res.json()).to.deep.equal({
        method: 'GET',
        status: 200,
        result: 'rejected',
        error: 'invalid_error_param',
      });
    });

    it('handles a generic fallback case', async function () {
      const res = await fetch(new URL('/notfound', url).toString());
      expect(await res.json()).to.deep.equal({
        method: 'GET',
        status: 404,
        result: 'unknown-url',
      });
    });
  });
});
