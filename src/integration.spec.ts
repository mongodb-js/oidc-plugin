import { expect } from 'chai';
import os from 'os';
import { promises as fs } from 'fs';
import {
  OIDCTestProvider,
  functioningAuthCodeBrowserFlow,
} from '../test/oidc-test-provider';
import type {
  OIDCMockProviderConfig,
  TokenMetadata,
} from '@mongodb-js/oidc-mock-provider';
import { MongoClient } from 'mongodb';
import type { OpenBrowserOptions } from './';
import { createMongoDBOIDCPlugin } from './';
import { OIDCMockProvider } from '@mongodb-js/oidc-mock-provider';
import { MongoCluster } from 'mongodb-runner';
import path from 'path';
import sinon from 'sinon';

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

describe('integration test with mongod', function () {
  this.timeout(90_000);

  let tmpDir: string;
  let cluster: MongoCluster;
  let spawnMongod: (serverOidcConfig: unknown) => Promise<MongoCluster>;

  before(async function () {
    if (process.platform !== 'linux') {
      // For the time being, OIDC is only supported on Linux on the server side.
      return this.skip();
    }

    tmpDir = path.join(os.tmpdir(), `test-mongodb-oidc-${Date.now()}`);
    await fs.mkdir(tmpDir, { recursive: true });

    spawnMongod = async (serverOidcConfig) =>
      await MongoCluster.start({
        version: '>= 7.0.0-rc5',
        downloadOptions: {
          allowedTags: [
            'release_candidate',
            'continuous_release',
            'production_release',
          ],
          enterprise: true,
        },
        topology: 'standalone',
        tmpDir,
        args: [
          '--setParameter',
          'authenticationMechanisms=SCRAM-SHA-256,MONGODB-OIDC',
          '--setParameter',
          `oidcIdentityProviders=${JSON.stringify(serverOidcConfig)}`,
          // enableTestCommands allows using http:// issuers such as http://localhost
          '--setParameter',
          'enableTestCommands=true',
        ],
      });
  });

  after(async function () {
    if (tmpDir) await fs.rm(tmpDir, { recursive: true, force: true });
  });

  context('can authenticate with browser-based IdP', function () {
    let provider: OIDCTestProvider;
    let connectionString: string;
    before(async function () {
      provider = await OIDCTestProvider.create();
      const serverOidcConfig = [
        {
          ...provider.getMongodbOIDCDBInfo(),
          requestScopes: ['mongodbGroups'],
          authorizationClaim: 'groups',
          audience: 'resource-server-audience-value',
          authNamePrefix: 'dev',
        },
      ];
      cluster = await spawnMongod(serverOidcConfig);
      connectionString = `mongodb://${cluster.hostport}/?authMechanism=MONGODB-OIDC`;
    });

    after(async function () {
      await Promise.all([cluster?.close(), provider.close()]);
    });

    it('can successfully authenticate', async function () {
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: functioningAuthCodeBrowserFlow,
      });
      const client = await MongoClient.connect(connectionString, {
        ...plugin.mongoClientOptions,
      });
      try {
        const status = await client
          .db('admin')
          .command({ connectionStatus: 1 });
        expect(status).to.deep.equal({
          ok: 1,
          authInfo: {
            authenticatedUsers: [{ user: 'dev/testuser', db: '$external' }],
            authenticatedUserRoles: [{ role: 'dev/testgroup', db: 'admin' }],
          },
        });
      } finally {
        await client.close();
      }
    });
  });

  context('can authenticate with a mock IdP', function () {
    let provider: OIDCMockProvider;
    let connectionString: string;
    let getTokenPayload: OIDCMockProviderConfig['getTokenPayload'];
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
      });

      const serverOidcConfig = [
        {
          issuer: provider.issuer,
          clientId: 'mockclientid',
          requestScopes: ['mongodbGroups'],
          authorizationClaim: 'groups',
          audience: 'resource-server-audience-value',
          authNamePrefix: 'dev',
        },
      ];

      cluster = await spawnMongod(serverOidcConfig);
      connectionString = `mongodb://${cluster.hostport}/?authMechanism=MONGODB-OIDC`;
    });

    after(async function () {
      await Promise.all([cluster?.close?.(), provider?.close?.()]);
    });

    beforeEach(function () {
      getTokenPayload = () => tokenPayload;
    });

    it('can successfully authenticate with a fake Auth Code Flow', async function () {
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
      });
      const client = await MongoClient.connect(connectionString, {
        ...plugin.mongoClientOptions,
      });
      try {
        const status = await client
          .db('admin')
          .command({ connectionStatus: 1 });
        expect(status).to.deep.equal({
          ok: 1,
          authInfo: {
            authenticatedUsers: [{ user: 'dev/testuser', db: '$external' }],
            authenticatedUserRoles: [{ role: 'dev/testgroup', db: 'admin' }],
          },
        });
      } finally {
        await client.close();
      }
    });

    it('can successfully authenticate with a fake Auth Code Flow with arbitrary-port redirectURI', async function () {
      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
        redirectURI: 'http://localhost:0/callback',
      });
      const client = await MongoClient.connect(connectionString, {
        ...plugin.mongoClientOptions,
      });
      try {
        const status = await client
          .db('admin')
          .command({ connectionStatus: 1 });
        expect(status).to.deep.equal({
          ok: 1,
          authInfo: {
            authenticatedUsers: [{ user: 'dev/testuser', db: '$external' }],
            authenticatedUserRoles: [{ role: 'dev/testgroup', db: 'admin' }],
          },
        });
      } finally {
        await client.close();
      }
    });

    it('can successfully authenticate with a fake Device Auth Flow', async function () {
      const plugin = createMongoDBOIDCPlugin({
        notifyDeviceFlow: () => {},
        allowedFlows: ['device-auth'],
      });
      const client = await MongoClient.connect(connectionString, {
        ...plugin.mongoClientOptions,
      });
      try {
        const status = await client
          .db('admin')
          .command({ connectionStatus: 1 });
        expect(status).to.deep.equal({
          ok: 1,
          authInfo: {
            authenticatedUsers: [{ user: 'dev/testuser', db: '$external' }],
            authenticatedUserRoles: [{ role: 'dev/testgroup', db: 'admin' }],
          },
        });
      } finally {
        await client.close();
      }
    });

    it('can successfully authenticate with a fake Device Auth Flow without an id_token - with a warning', async function () {
      getTokenPayload = () => ({
        ...tokenPayload,
        // id_token will not be included
        skipIdToken: true,
      });

      const { mongoClientOptions, logger } = createMongoDBOIDCPlugin({
        notifyDeviceFlow: () => {},
        allowedFlows: ['device-auth'],
      });
      const logEmitSpy = sinon.spy(logger, 'emit');
      const client = await MongoClient.connect(connectionString, {
        ...mongoClientOptions,
      });
      // without the id token, a warning will be logged
      sinon.assert.calledWith(
        logEmitSpy,
        'mongodb-oidc-plugin:missing-id-token'
      );
      try {
        const status = await client
          .db('admin')
          .command({ connectionStatus: 1 });
        expect(status).to.deep.equal({
          ok: 1,
          authInfo: {
            authenticatedUsers: [{ user: 'dev/testuser', db: '$external' }],
            authenticatedUserRoles: [{ role: 'dev/testgroup', db: 'admin' }],
          },
        });
      } finally {
        await client.close();
      }
    });

    it.only('can successfully authenticate with a fake Auth Code Flow without an id_token - with a warning', async function () {
      getTokenPayload = () => ({
        ...tokenPayload,
        // id_token will not be included
        skipIdToken: true,
      });

      const plugin = createMongoDBOIDCPlugin({
        openBrowserTimeout: 60_000,
        openBrowser: fetchBrowser,
        allowedFlows: ['auth-code'],
      });
      const client = await MongoClient.connect(connectionString, {
        ...plugin.mongoClientOptions,
      });
      try {
        const status = await client
          .db('admin')
          .command({ connectionStatus: 1 });
        expect(status).to.deep.equal({
          ok: 1,
          authInfo: {
            authenticatedUsers: [{ user: 'dev/testuser', db: '$external' }],
            authenticatedUserRoles: [{ role: 'dev/testgroup', db: 'admin' }],
          },
        });
      } finally {
        await client.close();
      }
    });
  });
});
