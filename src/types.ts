/** @public */
export interface MongoDBOIDCLogEventsMap {
  'mongodb-oidc-plugin:local-redirect-accessed': (event: {
    id: string;
  }) => void;
  'mongodb-oidc-plugin:oidc-callback-accepted': (event: {
    method: string;
    hasBody: boolean;
    errorCode?: string;
  }) => void;
  'mongodb-oidc-plugin:oidc-callback-rejected': (event: {
    method: string;
    hasBody: boolean;
    errorCode: string;
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
  'mongodb-oidc-plugin:open-browser': (event: {
    customOpener: boolean;
  }) => void;
  'mongodb-oidc-plugin:notify-device-flow': () => void;
  'mongodb-oidc-plugin:auth-attempt-started': (event: { flow: string }) => void;
  'mongodb-oidc-plugin:auth-attempt-succeeded': () => void;
  'mongodb-oidc-plugin:auth-attempt-failed': (event: { error: string }) => void;
  'mongodb-oidc-plugin:refresh-failed': (event: { error: string }) => void;
  'mongodb-oidc-plugin:skip-auth-attempt': (event: { reason: string }) => void;
  'mongodb-oidc-plugin:auth-failed': (event: { error: string }) => void;
  'mongodb-oidc-plugin:auth-succeeded': (event: {
    hasRefreshToken: boolean;
    expiresAt: string | null;
  }) => void;
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

// We're copying driver types here rather than importing them
// because we don't want to add a dependency on the driver from the
// plugin package itself here.
// TypeScript will still complain if they start mismatching,
// and these are standarized/spec'd, so unlikely to change frequently,
// esp. in breaking ways.

/**
 * A copy of the Node.js driver's `OIDCMechanismServerStep1`
 * @public
 */
export interface OIDCMechanismServerStep1 {
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  deviceAuthorizationEndpoint?: string;
  clientId: string;
  clientSecret?: string;
  requestScopes?: string[];
}

/**
 * A copy of the Node.js driver's `OIDCRequestTokenResult`
 * @public
 */
export interface OIDCRequestTokenResult {
  accessToken: string;
  expiresInSeconds?: number;
  refreshToken?: string;
}

/**
 * A copy of the Node.js driver's `OIDCRequestFunction`
 * @public
 */
export type OIDCRequestFunction = (
  principalName: string | undefined,
  idl: OIDCMechanismServerStep1,
  abortSignal?: OIDCAbortSignal | number
) => Promise<OIDCRequestTokenResult>;

/**
 * A copy of the Node.js driver's `OIDCRefreshFunction`
 * @public
 */
export type OIDCRefreshFunction = (
  principalName: string | undefined,
  idl: OIDCMechanismServerStep1,
  result: OIDCRequestTokenResult,
  abortSignal?: OIDCAbortSignal | number
) => Promise<OIDCRequestTokenResult>;

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
  /** @internal */
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
