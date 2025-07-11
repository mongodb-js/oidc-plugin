/** @public */
export interface MongoDBOIDCLogEventsMap {
  'mongodb-oidc-plugin:deserialization-failed': (event: {
    error: string;
  }) => void;
  'mongodb-oidc-plugin:state-updated': (event: {
    updateId: number;
    tokenSetId: string;
    timerDuration: number | undefined;
  }) => void;
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
    isAcceptedOIDCResponse: boolean;
  }) => void;
  'mongodb-oidc-plugin:unknown-url-accessed': (event: {
    method: string;
    path: string;
  }) => void;
  'mongodb-oidc-plugin:local-listen-started': (event: {
    url: string;
    urlPort: number;
  }) => void;
  'mongodb-oidc-plugin:local-listen-resolved-hostname': (event: {
    url: string;
    urlPort: number;
    hostname: string;
    interfaces: { family: number; address: string }[];
  }) => void;
  'mongodb-oidc-plugin:local-listen-failed': (event: {
    url: string;
    error: string;
  }) => void;
  'mongodb-oidc-plugin:local-listen-succeeded': (event: {
    url: string;
    interfaces: { family: number; address: string }[];
  }) => void;
  'mongodb-oidc-plugin:local-server-close': (event: { url: string }) => void;
  'mongodb-oidc-plugin:open-browser': (event: {
    customOpener: boolean;
  }) => void;
  'mongodb-oidc-plugin:open-browser-complete': () => void;
  'mongodb-oidc-plugin:notify-device-flow': () => void;
  'mongodb-oidc-plugin:auth-attempt-started': (event: {
    authStateId: string;
    flow: string;
  }) => void;
  'mongodb-oidc-plugin:auth-attempt-succeeded': (event: {
    authStateId: string;
  }) => void;
  'mongodb-oidc-plugin:auth-attempt-failed': (event: {
    authStateId: string;
    error: string;
  }) => void;
  'mongodb-oidc-plugin:refresh-skipped': (event: {
    triggeringUpdateId: number;
    expectedRefreshToken: string | null;
    actualRefreshToken: string | null;
  }) => void;
  'mongodb-oidc-plugin:refresh-started': (event: {
    triggeringUpdateId: number;
    refreshToken: string | null;
  }) => void;
  'mongodb-oidc-plugin:refresh-succeeded': (event: {
    triggeringUpdateId: number;
    refreshToken: string | null;
  }) => void;
  'mongodb-oidc-plugin:refresh-failed': (event: {
    error: string;
    triggeringUpdateId: number;
    refreshToken: string | null;
  }) => void;
  'mongodb-oidc-plugin:skip-auth-attempt': (event: {
    authStateId: string;
    reason: string;
  }) => void;
  'mongodb-oidc-plugin:auth-failed': (event: {
    authStateId: string;
    error: string;
  }) => void;
  'mongodb-oidc-plugin:auth-succeeded': (event: {
    authStateId: string;
    tokenType: string | null;
    refreshToken: string | null;
    expiresAt: string | null;
    passIdTokenAsAccessToken: boolean;
    tokens: {
      accessToken: string | undefined;
      idToken: string | undefined;
      refreshToken: string | undefined;
    };
    forceRefreshOrReauth: boolean;
    willRetryWithForceRefreshOrReauth: boolean;
    tokenSetId: string;
  }) => void;
  'mongodb-oidc-plugin:request-token-started': (event: {
    authStateId: string;
    isCurrentAuthAttemptSet: boolean;
    tokenSetId: string | undefined;
    username: string | undefined;
    issuer: string;
    clientId: string;
    requestScopes: string[] | undefined;
  }) => void;
  'mongodb-oidc-plugin:request-token-ended': (event: {
    authStateId: string;
    isCurrentAuthAttemptSet: boolean;
    tokenSetId: string | undefined;
    username: string | undefined;
    issuer: string;
    clientId: string;
    requestScopes: string[] | undefined;
  }) => void;
  'mongodb-oidc-plugin:discarding-token-set': (event: {
    tokenSetId: string;
  }) => void;
  'mongodb-oidc-plugin:destroyed': () => void;
  'mongodb-oidc-plugin:missing-id-token': () => void;
  'mongodb-oidc-plugin:outbound-http-request': (event: { url: string }) => void;
  'mongodb-oidc-plugin:inbound-http-request': (event: { url: string }) => void;
  'mongodb-oidc-plugin:outbound-http-request-failed': (event: {
    url: string;
    error: string;
  }) => void;
  'mongodb-oidc-plugin:outbound-http-request-completed': (event: {
    url: string;
    status: number;
    statusText: string;
  }) => void;
  'mongodb-oidc-plugin:received-server-params': (event: {
    params: OIDCCallbackParams;
  }) => void;
}

/** @public */
// eslint-disable-next-line @typescript-eslint/ban-types
export interface TypedEventEmitter<EventMap extends object> {
  // TypeScript uses something like this itself for its EventTarget definitions.
  on<K extends keyof EventMap>(event: K, listener: EventMap[K]): this;
  off?<K extends keyof EventMap>(event: K, listener: EventMap[K]): this;
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
 * A copy of the Node.js driver's `IdPServerInfo`
 * @public
 */
export interface IdPServerInfo {
  issuer: string;
  clientId: string;
  requestScopes?: string[];
}

/**
 * A copy of the Node.js driver's `IdPServerResponse`
 * @public
 */
export interface IdPServerResponse {
  accessToken: string;
  expiresInSeconds?: number;
  refreshToken?: string;
}

/**
 * A copy of the Node.js driver's `OIDCCallbackParams` using `OIDCAbortSignal` instead of `AbortSignal`
 * @public
 */
export interface OIDCCallbackParams {
  refreshToken?: string;
  timeoutContext?: OIDCAbortSignal;
  version: 1;
  username?: string;
  idpInfo?: IdPServerInfo;
}

/**
 * A copy of the Node.js driver's `OIDCRefreshFunction`
 * @public
 */
export type OIDCCallbackFunction = (
  params: OIDCCallbackParams
) => Promise<IdPServerResponse>;

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
  public readonly codeName: `MongoDBOIDC${string}`;

  constructor(
    message: string,
    { cause, codeName }: { cause?: unknown; codeName: string }
  ) {
    super(message, { cause });
    this.codeName = `MongoDBOIDC${codeName}`;
  }

  static isMongoDBOIDCError(value: unknown): value is MongoDBOIDCError {
    return (
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      value && typeof value === 'object' && (value as any)[MongoDBOIDCErrorTag]
    );
  }
}
