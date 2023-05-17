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
};

const client = await MongoClient.connect(
  'mongodb+srv://.../?authMechanism=MONGODB-OIDC',
  {
    ...createMongoDBOIDCPlugin(config).mongoClientOptions,
  }
);

// ...
```

See the TypeScript annontations for more API details.

[mongodb node.js driver]: https://github.com/mongodb/node-mongodb-native
