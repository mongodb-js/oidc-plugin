# @mongodb-js/oidc-plugin

A plugin for the [MongoDB Node.js driver][] to support human/browser-based
OIDC authentication flows.

OIDC support is a preview feature of MongoDB and not currently recommended for
production usage.

## Example usage

```ts
import { MongoClient } from 'mongodb';
import { createMongoDBOIDCPlugin } from '@mongodb-js/oidc-plugin';

// All config options are optional.
const config = {
  openBrowser: {
    command: 'open -a "Firefox"',
  },
  // allowedFlows: ['auth-code', 'device-auth'], // if Device Auth Grant flow is required
};

const client = await MongoClient.connect(
  'mongodb+srv://.../?authMechanism=MONGODB-OIDC',
  {
    ...createMongoDBOIDCPlugin(config).mongoClientOptions,
  }
);

// ...
```

## Token Caching

The plugin supports external token caching to share OIDC tokens between processes, which is particularly useful for parallel Jest workers or multiple Node.js processes.

### Example: File-based Token Cache

```ts
import { promises as fs } from 'fs';
import {
  createMongoDBOIDCPlugin,
  TokenCache,
  OidcToken,
} from '@mongodb-js/oidc-plugin';

class FileTokenCache implements TokenCache {
  constructor(private filePath: string) {}

  async get(): Promise<OidcToken | undefined> {
    try {
      const data = await fs.readFile(this.filePath, 'utf8');
      return JSON.parse(data);
    } catch {
      return undefined;
    }
  }

  async set(token: OidcToken): Promise<void> {
    await fs.writeFile(this.filePath, JSON.stringify(token));
  }
}

// Use the file-based cache
const plugin = createMongoDBOIDCPlugin({
  tokenCache: new FileTokenCache('./oidc-cache.json'),
  openBrowser: { command: 'open' },
});

const client = await MongoClient.connect(
  'mongodb+srv://.../?authMechanism=MONGODB-OIDC',
  {
    ...plugin.mongoClientOptions,
  }
);
```

The plugin will automatically:

- Check the cache for valid tokens before starting interactive authentication
- Store fresh tokens in the cache after successful authentication
- Handle cache errors gracefully without interrupting the authentication flow

**Security Note**: Token caches contain sensitive authentication data. Ensure appropriate file permissions and storage security when implementing persistent caches.

See the TypeScript annotations for more API details.

[mongodb node.js driver]: https://github.com/mongodb/node-mongodb-native
