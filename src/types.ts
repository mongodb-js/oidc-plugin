/** @public */
export interface MongoDBOIDCLogEventsMap {
  'mongodb-oidc-plugin:local-redirect-accessed': (event: {
    id: string;
  }) => void;
  'mongodb-oidc-plugin:oidc-callback-accepted': (event: {
    method: string;
    hasBody: boolean;
  }) => void;
  'mongodb-oidc-plugin:oidc-callback-rejected': (event: {
    method: string;
    hasBody: boolean;
  }) => void;
  'mongodb-oidc-plugin:unknown-url-accessed': (event: {
    method: string;
    path: string;
  }) => void;
  'mongodb-oidc-plugin:local-listen-started': (event: { url: string }) => void;
  'mongodb-oidc-plugin:local-listen-failed': (event: { url: string }) => void;
  'mongodb-oidc-plugin:local-listen-succeeded': (event: {
    url: string;
    interfaces: string[];
  }) => void;
  'mongodb-oidc-plugin:local-server-close': (event: { url: string }) => void;
}

/** @public */
export interface TypedEventEmitter<EventMap extends object> {
  // TypeScript uses something like this itself for its EventTarget definitions.
  on<K extends keyof EventMap>(event: K, listener: EventMap[K]): this;
  once<K extends keyof EventMap>(event: K, listener: EventMap[K]): this;
  emit<K extends keyof EventMap>(
    event: K,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ...args: EventMap[K] extends (...args: infer P) => any ? P : never
  ): unknown;
}

/** @public */
export type OIDCAbortSignal = {
  aborted: boolean;
  reason?: unknown;
  addEventListener(
    type: 'abort',
    callback: () => void,
    options?: { once: boolean }
  ): void;
  removeEventListener(type: 'abort', callback: () => void): void;
};

/** @internal */
const MongoDBOIDCErrorTag = Symbol.for('@@mdb.oidcplugin.MongoDBOIDCErrorTag');
/** @public */
export class MongoDBOIDCError extends Error {
  private [MongoDBOIDCErrorTag] = true;

  constructor(message: string) {
    super(message);
  }

  static isMongoDBOIDCError(value: unknown): value is MongoDBOIDCError {
    return (
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      value && typeof value === 'object' && (value as any)[MongoDBOIDCErrorTag]
    );
  }
}
