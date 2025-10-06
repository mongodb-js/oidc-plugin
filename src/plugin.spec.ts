import type {
  MongoDBOIDCPlugin,
  MongoDBOIDCPluginOptions,
  OIDCAbortSignal,
  IdPServerInfo,
  OIDCCallbackFunction,
  OpenBrowserOptions,
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
import { MongoLogWriter } from 'mongodb-log-writer';
import { PassThrough } from 'stream';
import { verifySuccessfulAuthCodeFlowLog } from '../test/log-hook-verification-helpers';
import { automaticRefreshTimeoutMS, MongoDBOIDCPluginImpl } from './plugin';
import sinon from 'sinon';
import { publicPluginToInternalPluginMap_DoNotUseOutsideOfTests } from './api';
import type {
  Server as HTTPServer,
  ServerResponse,
  IncomingMessage,
} from 'http';
import { createServer as createHTTPServer } from 'http';
import type { AddressInfo } from 'net';
import type {
  OIDCMockProviderConfig,
  TokenMetadata,
} from '@mongodb-js/oidc-mock-provider';
import { OIDCMockProvider } from '@mongodb-js/oidc-mock-provider';
import type { Server as HTTPSServer } from 'https';
import { createServer as createHTTPSServer } from 'https';

// node-fetch@3 is ESM-only...
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
const fetch: typeof import('node-fetch').default = (...args) =>
  // eslint-disable-next-line @typescript-eslint/consistent-type-imports
  eval("import('node-fetch')").then((fetch: typeof import('node-fetch')) =>
    fetch.default(...args)
  );

// A 'browser' implementation that just does HTTP requests and ignores the response.
async function fetchBrowser({ url }: OpenBrowserOptions): Promise<void> {
  (await fetch(url)).body?.resume();
}

// Shorthand to avoid having to specify `principalName` and `abortSignal`
// if they aren't being used in the first place.
function requestToken(
  plugin: MongoDBOIDCPlugin,
  oidcParams: IdPServerInfo,
  abortSignal?: OIDCAbortSignal,
  username?: string,
  refreshToken?: string
): ReturnType<OIDCCallbackFunction> {
  return plugin.mongoClientOptions.authMechanismProperties.OIDC_HUMAN_CALLBACK({
    timeoutContext: abortSignal,
    version: 1,
    idpInfo: oidcParams,
    username,
    refreshToken,
  });
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

function testAuthCodeFlow(
  fn: (opts: Partial<MongoDBOIDCPluginOptions>) => Mocha.Func
): void {
  for (const skipNonceInAuthCodeRequest of [true, false]) {
    describe(`with skipNonceInAuthCodeRequest: ${skipNonceInAuthCodeRequest.toString()}`, function () {
      it(
        'can successfully authenticate with auth code flow',
        fn({ skipNonceInAuthCodeRequest })
      );
    });
  }
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
    let stateIdCounter = 0;
    sinon.replace(
      MongoDBOIDCPluginImpl,
      'createOIDCAuthStateId',
      sinon.fake(() => `${stateIdCounter++}`)
    );
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
    sinon.restore();
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

    testAuthCodeFlow(
      (opts) =>
        async function () {
          pluginOptions = {
            ...pluginOptions,
            ...opts,
          };
          plugin = createMongoDBOIDCPlugin(pluginOptions);
          let idToken: string | undefined;
          plugin.logger.once('mongodb-oidc-plugin:auth-succeeded', (event) => {
            idToken = event.tokens.idToken;
          });

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

          expect(idToken).to.not.be.undefined;

          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion -- we know it's non-null from the above check
          const idTokenContents = getJWTContents(idToken!);
          if (opts.skipNonceInAuthCodeRequest) {
            expect(idTokenContents.nonce).to.be.undefined;
          } else {
            expect(idTokenContents.nonce).to.not.be.undefined;
          }
        }
    );

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
        { reason: 'not-expired', authStateId: '0' },
      ]);
    });

    it('can optionally use id tokens instead of access tokens', async function () {
      pluginOptions = {
        ...defaultOpts,
        allowedFlows: ['auth-code'],
        openBrowser: functioningAuthCodeBrowserFlow,
        passIdTokenAsAccessToken: true,
      };
      plugin = createMongoDBOIDCPlugin(pluginOptions);
      const result = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo()
      );
      const accessTokenContents = getJWTContents(result.accessToken);
      expect(accessTokenContents.sub).to.equal('testuser');
      expect(accessTokenContents.aud).to.equal(
        provider.getMongodbOIDCDBInfo().clientId
      );
      expect(accessTokenContents.client_id).to.equal(undefined);
      verifySuccessfulAuthCodeFlowLog(await readLog());
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
        { authStateId: '0', reason: 'refresh-succeeded' },
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
      expect(startedAuthAttempts as { authStateId: string }[]).to.deep.equal([
        { authStateId: '0', flow: 'auth-code' },
        { authStateId: '0', flow: 'auth-code' },
      ]);
    });

    context('with automatic token refresh', function () {
      let timeouts: {
        fn: () => void;
        timeout: number;
        refed: boolean;
        cleared: boolean;
      }[] = [];
      let setTimeout: sinon.SinonStub;
      let clearTimeout: sinon.SinonStub;

      beforeEach(function () {
        timeouts = [];
        setTimeout = sinon.stub().callsFake(function (this: null, fn, timeout) {
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
        clearTimeout = sinon.stub().callsFake(function (this: null, timer) {
          expect(this).to.equal(null);
          timer.cleared = true;
        });
        (
          publicPluginToInternalPluginMap_DoNotUseOutsideOfTests.get(
            plugin
          ) as any
        ).timers = { setTimeout, clearTimeout };
      });

      it('will automatically refresh tokens', async function () {
        // Set to a fixed value, high enough to not expire and allow refreshes
        provider.accessTokenTTLSeconds = 10000;
        const result1 = await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo()
        );

        expect(timeouts).to.have.lengthOf(2);
        // 0 -> browser timeout, 1 -> refresh timeout
        expect(timeouts[0].refed).to.equal(false);
        expect(timeouts[0].cleared).to.equal(false);
        expect(timeouts[0].timeout).to.equal(60_000);
        expect(timeouts[1].refed).to.equal(false);
        expect(timeouts[1].cleared).to.equal(false);
        // openid-client bases expiration time on the actual current time, so
        // allow for a small margin of error
        expect(timeouts[1].timeout).to.be.greaterThanOrEqual(9_600_000);
        expect(timeouts[1].timeout).to.be.lessThanOrEqual(9_800_000);
        const logger = plugin.logger as typeof plugin.logger & EventEmitter;
        const refreshStartedEvent = once(
          logger,
          'mongodb-oidc-plugin:refresh-started'
        );
        timeouts[1].fn();
        await refreshStartedEvent;
        await once(logger, 'mongodb-oidc-plugin:refresh-succeeded');

        const skipEvent = once(logger, 'mongodb-oidc-plugin:skip-auth-attempt');
        const result2 = await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo()
        );
        expect(result1).to.not.deep.equal(result2);
        expect(getJWTContents(result1.accessToken).sub).to.equal(
          getJWTContents(result2.accessToken).sub
        );

        expect(await skipEvent).to.deep.equal([
          { reason: 'not-expired', authStateId: '0' },
        ]);
      });

      it('clears token refresh timers on destroy', async function () {
        // Set to a fixed value, high enough to not expire and allow refreshes
        provider.accessTokenTTLSeconds = 10000;
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());

        expect(timeouts).to.have.lengthOf(2);
        expect(timeouts[1].refed).to.equal(false);
        expect(timeouts[1].cleared).to.equal(false);
        await plugin.destroy();

        expect(timeouts).to.have.lengthOf(2);
        expect(timeouts[1].refed).to.equal(false);
        expect(timeouts[1].cleared).to.equal(true);
      });
    });

    context('when re-created from a serialized state', function () {
      it('can return serialized state', async function () {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        const rawData = await plugin.serialize();
        const serializedData = JSON.parse(
          Buffer.from(rawData, 'base64').toString('utf8')
        );
        expect(serializedData.oidcPluginStateVersion).to.equal(1);
        expect(serializedData.state).to.have.lengthOf(1);
        expect(serializedData.state[0][0]).to.be.a('string');
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        expect(Object.keys(serializedData.state[0][1]).sort()).to.deep.equal([
          'currentTokenSet',
          'discardingTokenSets',
          'id',
          'lastIdTokenClaims',
          'serverOIDCMetadata',
        ]);
      });

      it('returns serialized state even after .destroy()', async function () {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        await plugin.destroy();
        const rawData = await plugin.serialize();
        const serializedData = JSON.parse(
          Buffer.from(rawData, 'base64').toString('utf8')
        );
        expect(serializedData.oidcPluginStateVersion).to.equal(1);
        expect(serializedData.state).to.have.lengthOf(1);
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
          { reason: 'not-expired', authStateId: '0' },
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
          { reason: 'refresh-succeeded', authStateId: '0' },
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

    context('with a dynamic flow selection function', function () {
      beforeEach(function () {
        (pluginOptions.allowedFlows = sinon.stub().resolves(['auth-code'])),
          (plugin = createMongoDBOIDCPlugin(pluginOptions));
      });
      it('will not call that callback when refreshing tokens', async function () {
        const skipAuthAttemptEvent = once(
          logger,
          'mongodb-oidc-plugin:skip-auth-attempt'
        );
        provider.accessTokenTTLSeconds = 1;
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect(await skipAuthAttemptEvent).to.deep.equal([
          { reason: 'refresh-succeeded', authStateId: '0' },
        ]);
        expect(pluginOptions.allowedFlows).to.have.been.calledOnce;
      });

      it('will call the callback before performing a full auth', async function () {
        const startedAuthAttempts: unknown[] = [];
        logger.on('mongodb-oidc-plugin:auth-attempt-started', (data) =>
          startedAuthAttempts.push(data)
        );

        provider.accessTokenTTLSeconds = 1;
        provider.refreshTokenTTLSeconds = 1;
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        await delay(1000);
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
        expect(startedAuthAttempts as { authStateId: string }[]).to.deep.equal([
          { flow: 'auth-code', authStateId: '0' },
          { flow: 'auth-code', authStateId: '0' },
        ]);
        expect(pluginOptions.allowedFlows).to.have.been.calledTwice;
      });
    });

    context('when the server metadata/user data changes', function () {
      beforeEach(function () {
        (pluginOptions.allowedFlows = sinon.stub().resolves(['auth-code'])),
          (plugin = createMongoDBOIDCPlugin(pluginOptions));
      });

      it('it will perform two different auth flows', async function () {
        await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo(),
          undefined,
          'usera'
        );
        expect(pluginOptions.allowedFlows).to.have.callCount(1);
        await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo(),
          undefined,
          'userb'
        );
        expect(pluginOptions.allowedFlows).to.have.callCount(2);
        await requestToken(
          plugin,
          provider.getMongodbOIDCDBInfo(),
          undefined,
          'userb'
        );
        expect(pluginOptions.allowedFlows).to.have.callCount(2);
        await requestToken(
          plugin,
          {
            ...provider.getMongodbOIDCDBInfo(),
            extraKey: 'asdf',
          } as IdPServerInfo,
          undefined,
          'userb'
        );
        expect(pluginOptions.allowedFlows).to.have.callCount(3);
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
        { flow: 'auth-code', authStateId: '0' },
      ]);
      expect(events.map((e) => e[0])).to.include(
        'mongodb-oidc-plugin:auth-attempt-failed'
      );
      expect(events).to.deep.include([
        'mongodb-oidc-plugin:auth-attempt-started',
        { flow: 'device-auth', authStateId: '0' },
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
      const nowS = Date.now() / 1000;
      const nowMS = nowS * 1000;
      expect(automaticRefreshTimeoutMS({})).to.equal(undefined);
      expect(automaticRefreshTimeoutMS({ expiresAt: nowS + 10000 })).to.equal(
        undefined
      );
      expect(
        automaticRefreshTimeoutMS(
          {
            refreshToken: 'asdf',
            expiresAt: nowS + 10000,
          },
          undefined,
          nowMS
        )
      ).to.equal(9700000);
      expect(
        automaticRefreshTimeoutMS(
          {
            refreshToken: 'asdf',
            expiresAt: nowS + 100,
          },
          undefined,
          nowMS
        )
      ).to.equal(50000);
      expect(
        automaticRefreshTimeoutMS(
          {
            refreshToken: 'asdf',
            expiresAt: nowS + 100,
            idTokenClaims: { exp: nowS + 500 },
          },
          true,
          nowMS
        )
      ).to.equal(250000);
      expect(
        automaticRefreshTimeoutMS(
          {
            refreshToken: 'asdf',
            expiresAt: nowS + 100,
            idTokenClaims: { exp: nowS + 500 },
          },
          false,
          nowMS
        )
      ).to.equal(50000);
      expect(
        automaticRefreshTimeoutMS({
          refreshToken: 'asdf',
          expiresAt: nowS + 10,
        })
      ).to.equal(undefined);
      expect(
        automaticRefreshTimeoutMS({
          refreshToken: 'asdf',
          expiresAt: nowS + 0,
        })
      ).to.equal(undefined);
      expect(
        automaticRefreshTimeoutMS({
          refreshToken: 'asdf',
          expiresAt: nowS + -10,
        })
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

    it('includes a helpful error message when attempting to reach out to invalid issuer', async function () {
      try {
        await requestToken(plugin, {
          clientId: 'clientId',
          issuer: 'https://doesnotexist.mongodb.com/',
        });
        expect.fail('missed exception');
      } catch (err: any) {
        expect(err.message).to.include(
          'Unable to fetch issuer metadata for "https://doesnotexist.mongodb.com/":'
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
          const issuer = `http://localhost:${
            (server.address() as AddressInfo).port
          }/`;
          response = {
            issuer,
            authorization_endpoint: 'https://somehost/',
            device_authorization_endpoint: 'https://somehost/',
            token_endpoint: 'https://somehost/',
            jwks_uri: 'https://somehost/',
            [endpoint]: 'http://somehost/',
          };
          try {
            await requestToken(plugin, {
              clientId: 'clientId',
              issuer,
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
      if (
        process.env.EVR_TASK_ID &&
        ['darwin', 'win32'].includes(process.platform)
      ) {
        // TODO(MONGOSH-2335): Unskip Okta integration tests on macOS/Windows in Evergreen
        // eslint-disable-next-line no-console
        console.info(
          'skipping Okta integration tests on macOS/Windows in Evergreen MONGOSH-2335'
        );
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

    testAuthCodeFlow(
      (opts) =>
        async function () {
          plugin = createMongoDBOIDCPlugin({
            ...defaultOpts,
            allowedFlows: ['auth-code'],
            openBrowser: (opts) =>
              oktaBrowserAuthCodeFlow({ ...opts, username, password }),
            ...opts,
          });
          const result = await requestToken(plugin, metadata);

          validateToken(getJWTContents(result.accessToken));
          verifySuccessfulAuthCodeFlowLog(await readLog());
        }
    );

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

      if (
        process.env.EVR_TASK_ID &&
        ['darwin', 'win32'].includes(process.platform)
      ) {
        // TODO(MONGOSH-2335): Unskip Azure integration tests on macOS/Windows in Evergreen
        // eslint-disable-next-line no-console
        console.info(
          'skipping Azure integration tests on macOS/Windows in Evergreen MONGOSH-2335'
        );
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

    testAuthCodeFlow(
      (opts) =>
        async function () {
          plugin = createMongoDBOIDCPlugin({
            ...defaultOpts,
            allowedFlows: ['auth-code'],
            openBrowser: (opts) =>
              azureBrowserAuthCodeFlow({ ...opts, username, password }),
            ...opts,
          });
          const result = await requestToken(plugin, metadata);

          validateToken(getJWTContents(result.accessToken));
          verifySuccessfulAuthCodeFlowLog(await readLog());
        }
    );

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

// eslint-disable-next-line mocha/max-top-level-suites
describe('OIDC plugin (mock OIDC provider)', function () {
  let provider: OIDCMockProvider;
  let getTokenPayload: OIDCMockProviderConfig['getTokenPayload'];
  let overrideRequestHandler: OIDCMockProviderConfig['overrideRequestHandler'];
  let additionalIssuerMetadata: OIDCMockProviderConfig['additionalIssuerMetadata'];
  let receivedHttpRequests: string[] = [];
  const tokenPayload = {
    expires_in: 3600,
    payload: {
      // Define the user information stored inside the access tokens
      groups: ['testgroup'],
      sub: 'testuser',
      aud: 'resource-server-audience-value',
    },
  };

  before(async function () {
    if (+process.version.slice(1).split('.')[0] < 16) {
      // JWK support for Node.js KeyObject.export() is only Node.js 16+
      // but the OIDCMockProvider implementation needs it.
      return this.skip();
    }
    provider = await OIDCMockProvider.create({
      getTokenPayload(metadata: TokenMetadata) {
        return getTokenPayload(metadata);
      },
      additionalIssuerMetadata() {
        return additionalIssuerMetadata?.() ?? {};
      },
      overrideRequestHandler(
        url: string,
        req: IncomingMessage,
        res: ServerResponse
      ) {
        receivedHttpRequests.push(url);
        return overrideRequestHandler?.(url, req, res);
      },
    });
  });

  after(async function () {
    await provider?.close?.();
  });

  beforeEach(function () {
    receivedHttpRequests = [];
    getTokenPayload = () => tokenPayload;
    overrideRequestHandler = undefined;
    additionalIssuerMetadata = undefined;
  });

  context('with a broken token refresh flow', function () {
    let plugin: MongoDBOIDCPlugin;

    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });

      overrideRequestHandler = (url, req, res) => {
        if (new URL(url).searchParams.get('grant_type') === 'refresh_token') {
          res.writeHead(500);
          res.end('Internal Server Error');
        }
      };
    });

    it('will keep using an unexpired token if the refresh endpoint is broken even if refresh is overdue', async function () {
      getTokenPayload = () => {
        return { ...tokenPayload, expires_in: 60 /* one minute */ };
      };
      const req = async () =>
        await requestToken(plugin, {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        });
      const result1 = await req();
      const result2 = await req();
      expect(result1).to.deep.equal(result2);
    });
  });

  context('with different supported built-in scopes', function () {
    let getScopes: () => Promise<string[]>;

    beforeEach(function () {
      getScopes = async function () {
        const plugin = createMongoDBOIDCPlugin({
          openBrowserTimeout: 60_000,
          openBrowser: fetchBrowser,
          allowedFlows: ['auth-code'],
          redirectURI: 'http://localhost:0/callback',
        });
        const result = await requestToken(plugin, {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        });
        const accessTokenContents = getJWTContents(result.accessToken);
        return String(accessTokenContents.scope).split(' ').sort();
      };
    });

    it('will get a list of built-in OpenID scopes by default', async function () {
      additionalIssuerMetadata = undefined;
      expect(await getScopes()).to.deep.equal(['offline_access', 'openid']);
    });

    it('will omit built-in scopes if the IdP does not announce support for them', async function () {
      additionalIssuerMetadata = () => ({ scopes_supported: ['openid'] });
      expect(await getScopes()).to.deep.equal(['openid']);
    });
  });

  context('when drivers re-request tokens early', function () {
    let plugin: MongoDBOIDCPlugin;

    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });
    });

    it('will return a different token even if the existing one is not yet expired', async function () {
      const result1 = await requestToken(plugin, {
        issuer: provider.issuer,
        clientId: 'mockclientid',
        requestScopes: [],
      });
      const result2 = await requestToken(plugin, {
        issuer: provider.issuer,
        clientId: 'mockclientid',
        requestScopes: [],
      });
      const result3 = await requestToken(
        plugin,
        {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        },
        undefined,
        undefined,
        result2.refreshToken
      );
      const result4 = await requestToken(
        plugin,
        {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        },
        undefined,
        undefined,
        result2.refreshToken
      );
      expect(result1).to.deep.equal(result2);
      expect(result2.accessToken).not.to.equal(result3.accessToken);
      expect(result2.refreshToken).not.to.equal(result3.refreshToken);
      expect(result3).to.deep.equal(result4);
    });

    it('will return only one new token per expired token even when called in parallel', async function () {
      const result1 = await requestToken(plugin, {
        issuer: provider.issuer,
        clientId: 'mockclientid',
        requestScopes: [],
      });
      const [result2, result3] = await Promise.all([
        requestToken(
          plugin,
          {
            issuer: provider.issuer,
            clientId: 'mockclientid',
            requestScopes: [],
          },
          undefined,
          undefined,
          result1.refreshToken
        ),
        requestToken(
          plugin,
          {
            issuer: provider.issuer,
            clientId: 'mockclientid',
            requestScopes: [],
          },
          undefined,
          undefined,
          result1.refreshToken
        ),
      ]);
      expect(result1.accessToken).not.to.equal(result2.accessToken);
      expect(result1.refreshToken).not.to.equal(result2.refreshToken);
      expect(result2).to.deep.equal(result3);
    });
  });

  context('HTTP request handling', function () {
    let badHTTPSServer: HTTPSServer;

    before(async function () {
      badHTTPSServer = createHTTPSServer(
        {
          key: await fs.readFile(
            // https://github.com/nodejs/node/blob/becb55aac3f7eb93b03223744c35c6194f11e3e9/test/fixtures/keys/agent2-key.pem
            path.resolve(__dirname, '..', 'test', 'self-signed-key.pem')
          ),
          cert: await fs.readFile(
            // https://github.com/nodejs/node/blob/becb55aac3f7eb93b03223744c35c6194f11e3e9/test/fixtures/keys/agent2-cert.pem
            path.resolve(__dirname, '..', 'test', 'self-signed-cert.pem')
          ),
        },
        (req, res) => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ message: 'Hello World' }));
        }
      );
      badHTTPSServer.listen(0, 'localhost');
      await once(badHTTPSServer, 'listening');
    });

    after(async function () {
      if (badHTTPSServer) {
        badHTTPSServer.close();
        await once(badHTTPSServer, 'close');
      }
    });

    it('will track all outgoing HTTP requests', async function () {
      const pluginHttpRequests: string[] = [];
      const localServerHttpRequests: string[] = [];
      const browserHttpRequests: string[] = [];

      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: async ({ url }) => {
          // eslint-disable-next-line no-constant-condition
          while (true) {
            browserHttpRequests.push(url);
            const response = await fetch(url, { redirect: 'manual' });
            response.body?.resume();
            const redirectTarget =
              response.status >= 300 &&
              response.status < 400 &&
              response.headers.get('location');
            if (redirectTarget)
              url = new URL(redirectTarget, response.url).href;
            else break;
          }
        },
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });
      plugin.logger.on('mongodb-oidc-plugin:outbound-http-request', (ev) =>
        pluginHttpRequests.push(ev.url)
      );
      plugin.logger.on('mongodb-oidc-plugin:inbound-http-request', (ev) =>
        localServerHttpRequests.push(ev.url)
      );
      await requestToken(plugin, {
        issuer: provider.issuer,
        clientId: 'mockclientid',
        requestScopes: [],
      });

      const removeSearchParams = (str: string) =>
        Object.assign(new URL(str), { search: '' }).toString();
      const allOutboundRequests = [
        ...pluginHttpRequests,
        ...browserHttpRequests,
      ]
        .map(removeSearchParams)
        .sort();
      const allInboundRequests = [
        ...localServerHttpRequests,
        ...receivedHttpRequests,
      ]
        .map(removeSearchParams)
        .sort();
      expect(allOutboundRequests).to.deep.equal(allInboundRequests);
    });

    // Regression test for https://jira.mongodb.org/browse/MONGOSH-2444
    it('correctly keeps tracking after serialization and deserialization', async function () {
      const tokenEndpointRequests: any[] = [];
      let serializedState: string | undefined;

      getTokenPayload = () => {
        return { ...tokenPayload, expires_in: 5 };
      };

      const runPlugin = async () => {
        const plugin = createMongoDBOIDCPlugin({
          openBrowserTimeout: 60_000,
          openBrowser: fetchBrowser,
          allowedFlows: ['auth-code'],
          redirectURI: 'http://localhost:0/callback',
          serializedState,
          throwOnIncompatibleSerializedState: true,
        });

        plugin.logger.on(
          'mongodb-oidc-plugin:outbound-http-request-completed',
          (ev) => {
            if (
              ev.status === 200 &&
              new URL(ev.url).pathname.endsWith('/token')
            )
              tokenEndpointRequests.push(ev);
          }
        );

        await requestToken(plugin, {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        });
        serializedState = await plugin.serialize();
      };

      expect(tokenEndpointRequests).to.have.lengthOf(0);
      await runPlugin();
      expect(tokenEndpointRequests).to.have.lengthOf(1);
      await runPlugin();
      expect(tokenEndpointRequests).to.have.lengthOf(2);
    });

    it('allows node-fetch as a custom HTTP fetch client', async function () {
      const customFetch = sinon.stub().callsFake(fetch);
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
        customFetch,
      });
      const result = await requestToken(plugin, {
        issuer: provider.issuer,
        clientId: 'mockclientid',
        requestScopes: [],
      });
      expect(result.accessToken).to.be.a('string');
      expect(customFetch).to.have.been.called;
    });

    it('allows global Node.js fetch as a custom HTTP fetch client', async function () {
      const customFetch: typeof globalThis.fetch = sinon
        .stub()
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        .callsFake(globalThis.fetch);
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
        customFetch,
      });
      const result = await requestToken(plugin, {
        issuer: provider.issuer,
        clientId: 'mockclientid',
        requestScopes: [],
      });
      expect(result.accessToken).to.be.a('string');
      expect(customFetch).to.have.been.called;
    });

    it('logs helpful error messages for HTTP failures', async function () {
      const outboundHTTPRequestsCompleted: any[] = [];

      getTokenPayload = () => Promise.reject(new Error('test failure'));
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });

      plugin.logger.on(
        'mongodb-oidc-plugin:outbound-http-request-completed',
        (ev) => outboundHTTPRequestsCompleted.push(ev)
      );

      try {
        await requestToken(plugin, {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        });
        expect.fail('missed exception');
      } catch (err: any) {
        expect(err.message).to.equal(
          'unexpected HTTP response status code: caused by HTTP response 500 (Internal Server Error): test failure'
        );
      }
      expect(outboundHTTPRequestsCompleted).to.deep.include({
        url: `${provider.issuer}/.well-known/openid-configuration`,
        status: 200,
        statusText: 'OK',
      });
      expect(outboundHTTPRequestsCompleted).to.deep.include({
        url: `${provider.issuer}/token`,
        status: 500,
        statusText: 'Internal Server Error',
      });
    });

    it('logs helpful error messages for TLS failures', async function () {
      const outboundHTTPRequestsFailed: any[] = [];
      const port = (badHTTPSServer.address() as AddressInfo).port;

      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });

      plugin.logger.on(
        'mongodb-oidc-plugin:outbound-http-request-failed',
        (ev) => outboundHTTPRequestsFailed.push(ev)
      );

      let selfSignedReason = 'self-signed certificate';
      try {
        await requestToken(plugin, {
          issuer: `https://localhost:${port}/`,
          clientId: 'mockclientid',
          requestScopes: [],
        });
        expect.fail('missed exception');
      } catch (err: any) {
        // Electron and Node.js provide different error messages
        selfSignedReason = err.message.includes('self-signed certificate')
          ? 'self-signed certificate'
          : 'self signed certificate';
        expect(err.message).to.include(
          `Unable to fetch issuer metadata for "https://localhost:${port}/": something went wrong (caused by: request to https://localhost:${port}/.well-known/openid-configuration failed, reason: ${selfSignedReason}`
        );
      }
      const entry = outboundHTTPRequestsFailed.find(
        (ev) =>
          ev.url ===
          `https://localhost:${port}/.well-known/openid-configuration`
      );
      expect(entry).to.exist;
      expect(entry.error).to.include(selfSignedReason);
    });

    it('logs helpful error messages for OIDC token parse failures', async function () {
      getTokenPayload = () => ({
        expires_in: tokenPayload.expires_in,
        payload: { ...tokenPayload.payload, nonce: undefined },
      });
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });

      try {
        await requestToken(plugin, {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        });
        expect.fail('missed exception');
      } catch (err: any) {
        expect(err.message).to.equal(
          'invalid response encountered (caused by: JWT "nonce" (nonce) claim missing)'
        );
      }
    });

    it('handles JSON failure responses from the IDP', async function () {
      overrideRequestHandler = (url, req, res) => {
        if (new URL(url).pathname.endsWith('/token')) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              error: 'jsonfailure',
              error_description: 'failure text',
            })
          );
        }
      };
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
        customFetch: sinon.stub().callsFake(fetch),
      });

      try {
        await requestToken(plugin, {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: [],
        });
        expect.fail('missed exception');
      } catch (err: any) {
        expect(err.message).to.equal(
          'server responded with an error in the response body: caused by HTTP response 400 : jsonfailure, failure text'
        );
      }
    });
  });
});
