import type {
  MongoDBOIDCPlugin,
  MongoDBOIDCPluginOptions,
  OIDCAbortSignal,
  OIDCMechanismServerStep1,
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
  functioningAuthCodeBrowserFlow,
  functioningDeviceAuthBrowserFlow,
  OIDCTestProvider,
} from '../test/oidc-test-provider';
import { AbortController } from './util';
import { MongoLogWriter } from 'mongodb-log-writer';
import { PassThrough } from 'stream';
import { verifySuccessfulAuthCodeFlowLog } from '../test/log-hook-verification-helpers';
import { automaticRefreshTimeoutMS } from './plugin';
import sinon from 'sinon';
import { publicPluginToInternalPluginMap_DoNotUseOutsideOfTests } from './api';

// Shorthand to avoid having to specify `principalName` and `abortSignal`
// if they aren't being used in the first place.
function requestToken(
  plugin: MongoDBOIDCPlugin,
  oidcParams: OIDCMechanismServerStep1,
  principalName?: string | undefined,
  abortSignal?: OIDCAbortSignal | number
): ReturnType<OIDCRequestFunction> {
  return plugin.mongoClientOptions.authMechanismProperties.REQUEST_TOKEN_CALLBACK(
    principalName,
    oidcParams,
    abortSignal
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
    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
        allowedFlows: ['auth-code'],
        openBrowser: functioningAuthCodeBrowserFlow,
      });
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

    it('will re-use tokens while they are valid if the same username was provided', async function () {
      const result1 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo(),
        'testuser'
      );
      const result2 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo(),
        'testuser'
      );
      expect(result1).to.deep.equal(result2);
    });
    it('will not re-use tokens if different usernames were provided', async function () {
      const result1 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo(),
        'testuser1'
      );
      const result2 = await requestToken(
        plugin,
        provider.getMongodbOIDCDBInfo(),
        'testuser2'
      );
      expect(result1).to.not.deep.equal(result2);
    });

    context('with automatic token refresh', function () {
      it('will automatically refresh tokens', async function () {
        const timeouts: {
          fn: () => void;
          timeout: number;
          refed: boolean;
          cleared: boolean;
        }[] = [];
        const setTimeout = sinon.stub().callsFake((fn, timeout) => {
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
          .callsFake((timer) => (timer.cleared = true));
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
        expect(timeouts[0].timeout).to.equal(9_700_000);
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
        openBrowser: false,
        notifyDeviceFlow() {
          throw new Error('device auth');
        },
      });
      try {
        await requestToken(plugin, provider.getMongodbOIDCDBInfo());
      } catch (err) {
        expect(err.message).to.equal('device auth');
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
        expect(err.message).to.equal('Could not retrieve valid access token');
      }
    });
  });

  context('when an unusable redirect URL is provided', function () {
    beforeEach(function () {
      plugin = createMongoDBOIDCPlugin({
        ...defaultOpts,
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
        undefined,
        driverController.signal
      );
      onBrowserOpenRequested = () => driverController.abort();
      try {
        await result;
        expect.fail('missed exception');
      } catch (err) {
        expect(err.message).to.match(/abort|cancel/);
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
        expect(err.message).to.match(/abort|cancel/);
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
        expect(err.message).to.equal('could not spawn');
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
        expect(err.message).to.equal('Opening browser failed with exit code 1');
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
        expect(err.message).to.equal('Opening browser failed with exit code 1');
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
        expect(err.message).to.equal('Opening browser timed out');
      }
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
});
