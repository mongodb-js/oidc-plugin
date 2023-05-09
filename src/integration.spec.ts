import { expect } from 'chai';
import { downloadMongoDb } from '../test/download-mongodb';
import path from 'path';
import os from 'os';
import { promises as fs } from 'fs';
import {
  OIDCTestProvider,
  functioningAuthCodeBrowserFlow,
} from '../test/oidc-test-provider';
import { spawn } from 'child_process';
import { once } from 'events';
import { createInterface as readline } from 'readline';
import { MongoClient } from 'mongodb';
import type { OpenBrowserOptions } from './';
import { createMongoDBOIDCPlugin } from './';
import { PassThrough } from 'stream';
import { OIDCMockProvider } from '@mongodb-js/oidc-mock-provider';

// node-fetch@3 is ESM-only...
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
const fetch: typeof import('node-fetch').default = (...args) =>
  // eslint-disable-next-line @typescript-eslint/consistent-type-imports
  eval("import('node-fetch')").then((fetch: typeof import('node-fetch')) =>
    fetch.default(...args)
  );

// Spawn a mongod process with a provided OIDC configuration.
async function spawnMongod(
  tmpdir: string,
  mongodExecutable: string,
  serverOidcConfig: unknown
): Promise<[stopServer: () => Promise<void>, connectionString: string]> {
  const dbdir = path.join(tmpdir, 'db');
  await fs.mkdir(dbdir, { recursive: true });
  const proc = spawn(
    mongodExecutable,
    [
      '--setParameter',
      `oidcIdentityProviders=${JSON.stringify(serverOidcConfig)}`,
      '--setParameter',
      'authenticationMechanisms=SCRAM-SHA-256,MONGODB-OIDC',
      // enableTestCommands allows using http:// issuers such as http://localhost
      '--setParameter',
      'enableTestCommands=true',
      '--dbpath',
      dbdir,
      '--port',
      '0',
    ],
    {
      cwd: dbdir,
      stdio: ['inherit', 'pipe', 'inherit'],
    }
  );
  const procExit = once(proc, 'exit');

  const port = await Promise.race([
    procExit.then(([code]) => {
      throw new Error(`mongod exited with code ${code}`);
    }),
    (async () => {
      // Parse the log output written by mongod to stdout until we know
      // which port it chose.
      const pt = new PassThrough();
      proc.stdout?.pipe(pt);
      if (process.env.CI) proc.stdout?.pipe(process.stderr);
      for await (const l of readline({ input: pt })) {
        const line = JSON.parse(l);
        if (line.id === 23016 /* Waiting for connections */) {
          proc.stdout.unpipe(pt); // Ignore all further output
          return line.attr.port;
        }
      }
    })(),
  ]);
  return [
    async () => {
      proc.kill();
      await procExit;
      return;
    },
    `mongodb://127.0.0.1:${port}/?authMechanism=MONGODB-OIDC`,
  ];
}

// A 'browser' implementation that just does HTTP requests and ignores the response.
async function fetchBrowser({ url }: OpenBrowserOptions): Promise<void> {
  (await fetch(url)).body?.resume();
}

describe('integration test with mongod', function () {
  this.timeout(90_000);

  let tmpdir: string;
  let mongodExecutable: string;

  before(async function () {
    if (process.platform !== 'linux') {
      // For the time being, OIDC is only supported on Linux on the server side.
      return this.skip();
    }

    // Create a temporary directory, download mongodb
    tmpdir = path.join(os.tmpdir(), `test-mongodb-oidc-${Date.now()}`);
    await fs.mkdir(tmpdir, { recursive: true });
    mongodExecutable = path.join(
      await downloadMongoDb(tmpdir, '>= 7.0.0-rc0', {
        allowedTags: [
          'release_candidate',
          'continuous_release',
          'production_release',
        ],
      }),
      'mongod'
    );
  });

  after(async function () {
    if (tmpdir) await fs.rm(tmpdir, { recursive: true, force: true });
  });

  context('can authenticate with browser-based IdP', function () {
    let provider: OIDCTestProvider;
    let stop: () => Promise<void>;
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
      [stop, connectionString] = await spawnMongod(
        tmpdir,
        mongodExecutable,
        serverOidcConfig
      );
    });

    after(async function () {
      await Promise.all([stop(), provider.close()]);
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
    let stop: () => Promise<void>;
    let connectionString: string;

    before(async function () {
      if (+process.version.slice(1).split('.')[0] < 16) {
        // JWK support for Node.js KeyObject.export() is only Node.js 16+
        // but the OIDCMockProvider implementation needs it.
        return this.skip();
      }
      provider = await OIDCMockProvider.create({
        getTokenPayload() {
          return {
            expires_in: 3600,
            payload: {
              // Define the user information stored inside the access tokens
              groups: ['testgroup'],
              sub: 'testuser',
              aud: 'resource-server-audience-value',
            },
          };
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

      [stop, connectionString] = await spawnMongod(
        tmpdir,
        mongodExecutable,
        serverOidcConfig
      );
    });

    after(async function () {
      await Promise.all([stop?.(), provider?.close?.()]);
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
  });
});
