import type {
  MongoDBOIDCPlugin,
  MongoDBOIDCPluginOptions,
  OIDCAbortSignal,
  OIDCCallbackContext,
  IdPServerInfo,
  OIDCRequestFunction,
} from './';
import { createMongoDBOIDCPlugin, hookLoggerToMongoLogWriter } from './';
import { once } from 'events';
import path from 'path';
import { expect } from 'chai';
import { EventEmitter } from 'events';
import { promises as fs } from 'fs';
import {
  abortBrowserFlow,
  azureBrowserAuthCodeFlow,
  azureBrowserDeviceAuthFlow,
  functioningAuthCodeBrowserFlow,
  functioningDeviceAuthBrowserFlow,
  OIDCTestProvider,
  oktaBrowserAuthCodeFlow,
  oktaBrowserDeviceAuthFlow,
} from '../test/oidc-test-provider';
import { AbortController, AbortSignal } from './util';
import { MongoLogWriter } from 'mongodb-log-writer';
import { PassThrough } from 'stream';
import { verifySuccessfulAuthCodeFlowLog } from '../test/log-hook-verification-helpers';
import { automaticRefreshTimeoutMS } from './plugin';
import sinon from 'sinon';
import { publicPluginToInternalPluginMap_DoNotUseOutsideOfTests } from './api';
import type { Server as HTTPServer } from 'http';
import { createServer as createHTTPServer } from 'http';
import type { AddressInfo } from 'net';

// Shorthand to avoid having to specify `principalName` and `abortSignal`
// if they aren't being used in the first place.
function requestToken(
  plugin: MongoDBOIDCPlugin,
  oidcParams: IdPServerInfo,
  abortSignal?: OIDCAbortSignal | number
): ReturnType<OIDCRequestFunction> {
  const clientInfo: OIDCCallbackContext = { version: 0 };
  if (typeof abortSignal === 'number') clientInfo.timeoutSeconds = abortSignal;
  else if (abortSignal) clientInfo.timeoutContext = abortSignal;
  return plugin.mongoClientOptions.authMechanismProperties.REQUEST_TOKEN_CALLBACK(
    oidcParams,
    clientInfo
  );
}

function getJWTContents(input: string): Record<string, unknown> {
  // Does not verify the signature, but that's fine for testing purposes
  return JSON.parse(
    Buffer.from(input.split('.')[1], 'base64').toString('utf8')
  );
}

async function delay(ms: number) {
  return await new Promise((resolve) => setTimeout(resolve, ms));
}

describe('OIDC plugin (local OIDC provider)', function () {
  this.timeout(90_000);

  let plugin: MongoDBOIDCPlugin;
  let readLog: () => Promise<Record<string, unknown>[]>;
  let logWriter: MongoLogWriter;
  let logger: EventEmitter;
  let provider: OIDCTestProvider;
  let originalElectronRunAsNode: string | undefined;
  let defaultOpts: MongoDBOIDCPluginOptions;

  beforeEach(async function () {
    provider = await OIDCTestProvider.create();
    logger = new EventEmitter();
    const logStream = new PassThrough();
    logWriter = new MongoLogWriter(
      'logid',
      null,
      logStream,
      () => new Date('2021-12-16T14:35:08.763Z')
    );
    hookLoggerToMongoLogWriter(logger, logWriter, 'test');
    readLog = async () => {
      await logWriter.flush();
      const logRawData: string = logStream.setEncoding('utf8').read();
      return logRawData
        .split('\n')
        .filter(Boolean)
        .map((str) => JSON.parse(str));
    };

    defaultOpts = {
      logger,
      // Opening browsers in CI systems can take a while...
      openBrowserTimeout: 60_000,
    };

    // Needed so that the tests which use process.execPath to run
    // child processes can run Node.js scripts even in test-electron.
    originalElectronRunAsNode = process.env.ELECTRON_RUN_AS_NODE;
    process.env.ELECTRON_RUN_AS_NODE = '1';
  });

  afterEach(async function () {
    await provider.close();
    if (originalElectronRunAsNode !== undefined)
      process.env.ELECTRON_RUN_AS_NODE = originalElectronRunAsNode;
    else delete process.env.ELECTRON_RUN_AS_NODE;
  });

  context('with functioning auth code flow', function () {
    let pluginOptions: MongoDBOIDCPluginOptions;
    beforeEach(function () {
      pluginOptions = {
        ...defaultOpts,
        allowedFlows: ['auth-code'],
        openBrowser: functioningAuthCodeBrowserFlow,
      };
      plugin = createMongoDBOIDCPlugin(pluginOptions);
    });

    it('can request tokens through the browser', async function () {
      const result = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      const accessTokenContents = getJWTContents(result.accessToken);
      expect(accessTokenContents.sub).to.equal('testuser');
      expect(accessTokenContents.client_id).to.equal(
        provider.getMongodbOIDCDBInfo().clientId
      );
      verifySuccessfulAuthCodeFlowLog(await readLog());
    });

    it('will re-use tokens while they are valid if no username was provided', async function () {
      const skipAuthAttemptEvent = once(
        logger,
        'mongodb-oidc-plugin:skip-auth-attempt'
      );
      const result1 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      const result2 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      expect(result1).to.deep.equal(result2);
      expect(await skipAuthAttemptEvent).to.deep.equal([
        { reason: 'not-expired' },
      ]);
    });

    it('will refresh tokens if they are expiring', async function () {
      const skipAuthAttemptEvent = once(
        logger,
        'mongodb-oidc-plugin:skip-auth-attempt'
      );
      provider.accessTokenTTLSeconds = 1;
      const result1 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      const result2 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      expect(result1).to.not.deep.equal(result2);
      expect(getJWTContents(result1.accessToken).sub).to.equal(
        getJWTContents(result2.accessToken).sub
      );
      expect(await skipAuthAttemptEvent).to.deep.equal([
        { reason: 'refresh-succeeded' },
      ]);
    });

    it('will fall back to a full re-auth if the refresh token is outdated', async function () {
      const startedAuthAttempts: unknown[] = [];
      logger.on('mongodb-oidc-plugin:auth-attempt-started', (data) =>
        startedAuthAttempts.push(data)
      );

      provider.accessTokenTTLSeconds = 1;
      provider.refreshTokenTTLSeconds = 1;
      const result1 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      await delay(1000);
      const result2 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      expect(result1).to.not.deep.equal(result2);
      expect(getJWTContents(result1.accessToken).sub).to.equal(
        getJWTContents(result2.accessToken).sub
      );
      expect(startedAuthAttempts).to.deep.equal([
        { flow: 'auth-code' },
        { flow: 'auth-code' },
      ]);
    });

    context('with automatic token refresh', function () {
      it('will automatically refresh tokens', async function () {
        const timeouts: {
          fn: () => void;
          timeout: number;
          refed: boolean;
          cleared: boolean;
        }[] = [];
        const setTimeout = sinon
          .stub()
          .callsFake(function (this: null, fn, timeout) {
            expect(this).to.equal(null);
            const entry = {
              fn,
              timeout,
              refed: true,
              cleared: false,
              ref() {
                this.refed = true;
              },
              unref() {
                this.refed = false;
              },
            };
            timeouts.push(entry);
            return entry;
          });
        const clearTimeout = sinon
          .stub()
          .callsFake(function (this: null, timer) {
            expect(this).to.equal(null);
            timer.cleared = true;
          });
        (
          publicPluginToInternalPluginMap_DoNotUseOutsideOfTests.get(
            plugin
          ) as any
        ).timers = { setTimeout, clearTimeout };

        // Set to a fixed value, high enough to not expire and allow refreshes
        provider.accessTokenTTLSeconds = 10000;
        const result1 = await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo()
        );

        expect(timeouts).to.have.lengthOf(1);
        expect(timeouts[0].refed).to.equal(false);
        expect(timeouts[0].cleared).to.equal(false);
        // openid-client bases expiration time on the actual current time, so
        // allow for a small margin of error
        expect(timeouts[0].timeout).to.be.greaterThanOrEqual(9_600_000);
        expect(timeouts[0].timeout).to.be.lessThanOrEqual(9_800_000);
        const refreshStartedEvent = once(
          plugin.logger,
          'mongodb-oidc-plugin:refresh-started'
        );
        timeouts[0].fn();
        await refreshStartedEvent;
        await once(plugin.logger, 'mongodb-oidc-plugin:refresh-succeeded');

        const skipEvent = once(
          plugin.logger,
          'mongodb-oidc-plugin:skip-auth-attempt'
        );
        const result2 = await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo()
        );
        expect(result1).to.not.deep.equal(result2);
        expect(getJWTContents(result1.accessToken).sub).to.equal(
          getJWTContents(result2.accessToken).sub
        );

        expect(await skipEvent).to.deep.equal([{ reason: 'not-expired' }]);
      });
    });

    context('when re-created from a serialized state', function () {
      it('can return serialized state', async function () {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        const rawData = await plugin.serialize();
        const serializedData = JSON.parse(
          Buffer.from(rawData, 'base64').toString('utf8')
        );
        expect(serializedData.oidcPluginStateVersion).to.equal(0);
        expect(serializedData.state).to.have.lengthOf(1);
        expect(serializedData.state[0][0]).to.be.a('string');
        expect(Object.keys(serializedData.state[0][1]).sort()).to.deep.equal([
          'currentTokenSet',
          'lastIdTokenClaims',
          'serverOIDCMetadata',
        ]);
      });

      it('can use access tokens from the serialized state', async function () {
        const skipAuthAttemptEvent = once(
          logger,
          'mongodb-oidc-plugin:skip-auth-attempt'
        );
        const result1 = await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo()
        );
        const plugin2 = createMongoDBOIDCPlugin({
          ...pluginOptions,
          serializedState: await plugin.serialize(),
        });
        const result2 = await requestToken(
          plugin2,
          provider.getMongodbOIDCDBInfo()
        );
        expect(result1).to.deep.equal(result2);
        expect(await skipAuthAttemptEvent).to.deep.equal([
          { reason: 'not-expired' },
        ]);
      });

      it('can use refresh tokens from the serialized state', async function () {
        const skipAuthAttemptEvent = once(
          logger,
          'mongodb-oidc-plugin:skip-auth-attempt'
        );
        provider.accessTokenTTLSeconds = 1;
        const result1 = await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo()
        );
        const plugin2 = createMongoDBOIDCPlugin({
          ...pluginOptions,
          serializedState: await plugin.serialize(),
        });
        const result2 = await requestToken(
          plugin2,
          provider.getMongodbOIDCDBInfo()
        );
        expect(result1).to.not.deep.equal(result2);
        expect(getJWTContents(result1.accessToken).sub).to.equal(
          getJWTContents(result2.accessToken).sub
        );
        expect(await skipAuthAttemptEvent).to.deep.equal([
          { reason: 'refresh-succeeded' },
        ]);
      });

      it('rejects invalid serialized state', async function () {
        const error = once(
          logger,
          'mongodb-oidc-plugin:deserialization-failed'
        );
        createMongoDBOIDCPlugin({
          serializedState: 'invalid',
          logger,
        });
        expect((await error)[0].error).to.include(
          'Stored OIDC data could not be deserialized'
        );
      });

      it('rejects serialized state from a newer version of the plugin', async function () {
        const error = once(
          logger,
          'mongodb-oidc-plugin:deserialization-failed'
        );
        createMongoDBOIDCPlugin({
          serializedState: Buffer.from(
            JSON.stringify({ oidcPluginStateVersion: 10000 }),
            'utf8'
          ).toString('base64'),
          logger,
        });
        expect((await error)[0].error).to.include(
          'Stored OIDC data could not be deserialized because of a version mismatch'
        );
      });

      it('throws on deserialization errors when requested', function () {
        try {
          createMongoDBOIDCPlugin({
            serializedState: 'invalid',
            throwOnIncompatibleSerializedState: true,
          });
          expect.fail('missed exception');
        } catch (err) {
          expect((err as any).message).to.include(
            'Stored OIDC data could not be deserialized'
          );
        }
      });
    });
  });

  context('when the user aborts an auth code flow', function () {
    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser: abortBrowserFlow,
        notifyDeviceFlow: () => Promise.reject(new Error('unreachable')),
      });
    });

    it('respect user aborts and does not attempt device flow auth', async function () {
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect.fail('missed exception');
      } catch (err: any) {
        expect(err.message).to.include('End-User aborted interaction');
      }
    });
  });

  context('with functioning device auth flow', function () {
    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['device-auth'],
        notifyDeviceFlow: functioningDeviceAuthBrowserFlow,
      });
    });

    it('can request tokens through the browser ', async function () {
      const result = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      const accessTokenContents = getJWTContents(result.accessToken);
      expect(accessTokenContents.sub).to.equal('testuser');
      expect(accessTokenContents.client_id).to.equal(
        provider.getMongodbOIDCDBInfo().clientId
      );
    });
  });

  context('with incomplete configuration', function () {
    it('skips auth code flow if browser interactions is disallowed', async function () {
      const plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['auth-code', 'device-auth'],
        openBrowser: false,
        notifyDeviceFlow() {
          throw new Error('device auth');
        },
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
      } catch (err) {
        expect((err as any).message).to.equal('device auth');
      }
    });

    it('cannot auth if all prerequisites for flows are missing', async function () {
      const plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser: false,
        notifyDeviceFlow: undefined,
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
      } catch (err) {
        expect((err as any).message).to.equal(
          'Could not retrieve valid access token'
        );
      }
    });
  });

  context('when an unusable redirect URL is provided', function () {
    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['auth-code', 'device-auth'],
        redirectURI: 'http://192.0.2.1:1/', // fixed test IP address
        openBrowser: () => Promise.reject(new Error('unreachable')),
        notifyDeviceFlow: functioningDeviceAuthBrowserFlow,
      });
    });

    it('respect user aborts and does not attempt device flow auth', async function () {
      const events: [string, unknown][] = [];
      for (const event of [
        'mongodb-oidc-plugin:auth-attempt-started',
        'mongodb-oidc-plugin:auth-attempt-failed',
        'mongodb-oidc-plugin:auth-attempt-succeeded',
      ]) {
        logger.on(event, (data) => events.push([event, data]));
      }
      await requestToken(plugin, provider.getMongodbOIDCDBInfo());
      expect(events).to.deep.include([
        'mongodb-oidc-plugin:auth-attempt-started',
        { flow: 'auth-code' },
      ]);
      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:auth-attempt-failed'
      );
      expect(events).to.deep.include([
        'mongodb-oidc-plugin:auth-attempt-started',
        { flow: 'device-auth' },
      ]);
      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:auth-attempt-succeeded'
      );
    });
  });

  context('when being aborted externally', function () {
    let openBrowserAborted = false;
    let onBrowserOpenRequested: undefined | (() => void);
    let pluginAbortController: AbortController;

    beforeEach(function () {
      openBrowserAborted = true;
      pluginAbortController = new AbortController();
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser: ({ signal }) => {
          signal.addEventListener('abort', () => (openBrowserAborted = true));
          onBrowserOpenRequested?.();
          return Promise.resolve();
        },
        notifyDeviceFlow: functioningDeviceAuthBrowserFlow,
        signal: pluginAbortController.signal,
      });
    });

    it('handles abort coming from the driver', async function () {
      const driverController = new AbortController();
      const result = requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo(),
        driverController.signal
      );
      onBrowserOpenRequested = () => driverController.abort();
      try {
        await result;
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.match(/abort|cancel/);
      }
      expect(openBrowserAborted).to.equal(true);
    });

    it('handles abort coming from the user', async function () {
      const result = requestToken(plugin, provider.getMongodbOIDCDBInfo());
      onBrowserOpenRequested = () => pluginAbortController.abort();
      try {
        await result;
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.match(/abort|cancel/);
      }
      expect(openBrowserAborted).to.equal(true);
    });

    it('handles failure to spawn browser', async function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser() {
          const ee = new EventEmitter();
          setImmediate(() => ee.emit('error', new Error('could not spawn')));
          return Promise.resolve(ee);
        },
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.equal(
          "Opening browser failed with 'could not spawn'"
        );
      }
    });

    it('handles browser exiting with non-zero exit code', async function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser() {
          const ee = new EventEmitter();
          setImmediate(() => ee.emit('exit', 1));
          return Promise.resolve(ee);
        },
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.equal(
          'Opening browser failed with exit code 1'
        );
      }
    });

    it('handles script exiting with non-zero exit code', async function () {
      const argvFile = path.resolve(__dirname, '..', 'test', 'argv.json');
      const fauxBrowserFile = path.resolve(
        __dirname,
        '..',
        'test',
        'faux-browser.js'
      );
      await fs.rm(argvFile, { force: true });
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser: {
          command: `"${process.execPath}" "${fauxBrowserFile}"`,
        },
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.include(
          'Opening browser failed with exit code 1'
        );
        expect((err as any).message).to.include('faux-browser.js');
      }
      const argv = JSON.parse(await fs.readFile(argvFile, 'utf8'));
      await fs.rm(argvFile, { force: true });
      expect(argv[0]).to.include(path.basename(process.execPath));
      expect(argv[1]).to.include(path.basename(fauxBrowserFile));
      expect(argv[2]).to.include('http://localhost');
    });

    it('handles the browser not loading the URL', async function () {
      const fauxBrowserFile = path.resolve(__dirname, '..', 'test', 'sleep.js');
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        openBrowser: {
          command: `"${process.execPath}" "${fauxBrowserFile}"`,
          abortable: true,
        },
        openBrowserTimeout: 500,
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.equal('Opening browser timed out');
      }
    });

    it('handles a rejecting auth flow callback', async function () {
      const allowedFlows = sinon
        .stub()
        .rejects(new Error('no authentication wanted'));
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows,
      });
      const result = requestToken(plugin, provider.getMongodbOIDCDBInfo());
      try {
        await result;
        expect.fail('missed exception');
      } catch (err) {
        expect((err as any).message).to.equal('no authentication wanted');
      }
      expect(allowedFlows).to.have.been.calledOnce;
      expect(allowedFlows.getCall(0).args[0].signal).to.be.instanceOf(
        AbortSignal
      );
    });
  });

  context('when the server announces invalid configurations', function () {
    let notifyDeviceFlow: sinon.SinonStub;
    let openBrowser: sinon.SinonStub;

    beforeEach(function () {
      notifyDeviceFlow = sinon
        .stub()
        .rejects(new Error('unreachable notifyDeviceFlow'));
      openBrowser = sinon.stub().rejects(new Error('unreachable openBrowser'));
    });

    context('with all flows enabled', function () {
      beforeEach(function () {
        plugin = createMongoDBOIDCPlugin({
          ...defaultOpts,
          openBrowser,
          notifyDeviceFlow,
          allowedFlows: ['auth-code', 'device-auth'],
        });
      });

      it('does not fall back from auth code flow if the endpoint is invalid', async function () {
        try {
          await requestToken(plugin, {
            clientId: 'asdf',
            issuer: 'not a url',
          });
          expect.fail('missed exception');
        } catch (err: any) {
          expect(err.message).to.include('(validating: issuer)');
        }
        expect(notifyDeviceFlow).to.not.have.been.called;
        expect(openBrowser).to.not.have.been.called;
      });

      it('does not fall back from auth code flow if the endpoint is missing', async function () {
        try {
          await requestToken(plugin, {
            clientId: 'asdf',
            issuer: '',
          });
          expect.fail('missed exception');
        } catch (err: any) {
          expect(err.message).to.include("'issuer' is missing");
        }
        expect(notifyDeviceFlow).to.not.have.been.called;
        expect(openBrowser).to.not.have.been.called;
      });
    });
  });

  describe('automaticRefreshTimeoutMS', function () {
    it('returns the correct automatic refresh timeout', function () {
      expect(automaticRefreshTimeoutMS({})).to.equal(undefined);
      expect(automaticRefreshTimeoutMS({ expires_in: 10000 })).to.equal(
        undefined
      );
      expect(
        automaticRefreshTimeoutMS({ refresh_token: 'asdf', expires_in: 10000 })
      ).to.equal(9700000);
      expect(
        automaticRefreshTimeoutMS({ refresh_token: 'asdf', expires_in: 100 })
      ).to.equal(50000);
      expect(
        automaticRefreshTimeoutMS({ refresh_token: 'asdf', expires_in: 10 })
      ).to.equal(undefined);
      expect(
        automaticRefreshTimeoutMS({ refresh_token: 'asdf', expires_in: 0 })
      ).to.equal(undefined);
      expect(
        automaticRefreshTimeoutMS({ refresh_token: 'asdf', expires_in: -10 })
      ).to.equal(undefined);
    });
  });

  describe('issuer URL validation', function () {
    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
      });
    });

    it('rejects an issuer endpoint without https:', async function () {
      try {
        await requestToken(plugin, {
          clientId: 'clientId',
          issuer: 'http://somehost/',
        });
        expect.fail('missed exception');
      } catch (err: any) {
        expect(err.message).to.equal(
          "Need to specify https: when accessing non-local URL 'http://somehost/' (validating: issuer)"
        );
      }
    });

    context('with an issuer that reports custom metadata', function () {
      let server: HTTPServer;
      let response: Record<string, unknown>;

      beforeEach(async function () {
        response = {};
        server = createHTTPServer((req, res) => {
          res.setHeader('content-type', 'application/json');
          res.end(JSON.stringify(response));
        });
        server.listen();
        await once(server, 'listening');
      });

      afterEach(async function () {
        server.close();
        await once(server, 'close');
      });

      for (const endpoint of [
        'authorization_endpoint',
        'device_authorization_endpoint',
        'token_endpoint',
        'jwks_uri',
      ]) {
        it(`rejects an ${endpoint} endpoint which reports non-https endpoints`, async function () {
          response = {
            authorization_endpoint: 'https://somehost/',
            device_authorization_endpoint: 'https://somehost/',
            token_endpoint: 'https://somehost/',
            jwks_uri: 'https://somehost/',
            [endpoint]: 'http://somehost/',
          };
          try {
            await requestToken(plugin, {
              clientId: 'clientId',
              issuer: `http://localhost:${
                (server.address() as AddressInfo).port
              }/`,
            });
            expect.fail('missed exception');
          } catch (err: any) {
            expect(err.message).to.equal(
              `Need to specify https: when accessing non-local URL 'http://somehost/' (validating: ${endpoint})`
            );
          }
        });
      }
    });
  });

  describe('Okta integration tests', function () {
    let metadata: IdPServerInfo;
    let username: string;
    let password: string;
    let issuer: string;
    let clientId: string;
    let validateToken: (token: Record<string, unknown>) => void;

    // See test/okta-setup.md for instructions on generating test config and credentials
    before(function () {
      if (!process.env.OKTA_TEST_CONFIG || !process.env.OKTA_TEST_CREDENTIALS) {
        if (process.env.EVR_TASK_ID)
          throw new Error('Missing Okta credentials');
        // eslint-disable-next-line no-console
        console.info('skipping Okta integration tests due to missing config');
        return this.skip();
      }

      [issuer, clientId] = JSON.parse(process.env.OKTA_TEST_CONFIG || '');
      [username, password] = JSON.parse(
        process.env.OKTA_TEST_CREDENTIALS || ''
      );
      metadata = {
        clientId,
        issuer,
        requestScopes: ['email'],
      };
      validateToken = (token) => {
        expect(token.sub).to.equal(username);
        expect(token.aud).to.equal(clientId);
        expect(token.cid).to.equal(clientId);
        expect(token.iss).to.equal(issuer);
        expect((token.scp as string[]).sort()).to.deep.equal([
          'email',
          'offline_access',
          'openid',
        ]);
        expect(token.groups).to.deep.equal(['root']);
      };
    });

    it('can successfully authenticate with Okta using auth code flow', async function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['auth-code'],
        openBrowser: (opts) =>
          oktaBrowserAuthCodeFlow({ ...opts, username, password }),
      });
      const result = await requestToken(plugin, metadata);

      validateToken(getJWTContents(result.accessToken));
      verifySuccessfulAuthCodeFlowLog(await readLog());
    });

    it('can successfully authenticate with Okta using device auth flow', async function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['device-auth'],
        notifyDeviceFlow: (opts) =>
          oktaBrowserDeviceAuthFlow({ ...opts, username, password }),
      });
      const result = await requestToken(plugin, metadata);
      validateToken(getJWTContents(result.accessToken));
    });
  });

  describe('Azure integration tests', function () {
    let metadata: IdPServerInfo;
    let username: string;
    let password: string;
    let issuer: string;
    let clientId: string;
    let requestScopes: string[];
    let validateToken: (token: Record<string, unknown>) => void;

    // See comments on MONGOSH-1387 for instructions on generating test config and credentials
    before(function () {
      if (
        !process.env.AZURE_TEST_CONFIG ||
        !process.env.AZURE_TEST_CREDENTIALS
      ) {
        if (process.env.EVR_TASK_ID)
          throw new Error('Missing Azure credentials');
        // eslint-disable-next-line no-console
        console.info('skipping Azure integration tests due to missing config');
        return this.skip();
      }

      [issuer, clientId, requestScopes] = JSON.parse(
        process.env.AZURE_TEST_CONFIG || ''
      );
      [username, password] = JSON.parse(
        process.env.AZURE_TEST_CREDENTIALS || ''
      );
      metadata = {
        clientId,
        issuer,
        requestScopes,
      };
      validateToken = (token) => {
        expect(token.preferred_username).to.equal(username);
        expect(token.sub).to.be.a('string'); // Azure 'sub' and 'groups' fields are opaque identifiers
        expect(token.aud).to.equal(clientId);
        expect(token.azp).to.equal(clientId);
        expect(token.iss).to.equal(issuer);
        expect(token.ver).to.equal('2.0');
        expect(token.groups).to.be.an('array');
        expect((token.groups as unknown[])[0]).to.be.a('string');
      };
    });

    it('can successfully authenticate with Azure using auth code flow', async function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['auth-code'],
        openBrowser: (opts) =>
          azureBrowserAuthCodeFlow({ ...opts, username, password }),
      });
      const result = await requestToken(plugin, metadata);

      validateToken(getJWTContents(result.accessToken));
      verifySuccessfulAuthCodeFlowLog(await readLog());
    });

    it('can successfully authenticate with Azure using device auth flow', async function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['device-auth'],
        notifyDeviceFlow: (opts) =>
          azureBrowserDeviceAuthFlow({ ...opts, username, password }),
      });
      const result = await requestToken(plugin, metadata);
      validateToken(getJWTContents(result.accessToken));
    });
  });
});
