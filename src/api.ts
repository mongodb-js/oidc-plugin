import type {
  IncomingMessage as HttpIncomingMessage,
  ServerResponse as HttpServerResponse,
} from 'http';
import { MongoDBOIDCPluginImpl } from './plugin';
import type {
  MongoDBOIDCLogEventsMap,
  OIDCAbortSignal,
  OIDCCallbackFunction,
  TypedEventEmitter,
} from './types';
import type { RequestOptions } from 'https';

/**
 * @public
 * @deprecated Use a custom `fetch` function instead
 */
export type HttpOptions = Partial<
  Pick<
    RequestOptions,
    | 'agent'
    | 'ca'
    | 'cert'
    | 'crl'
    | 'headers'
    | 'key'
    | 'lookup'
    | 'passphrase'
    | 'pfx'
    | 'timeout'
  >
>;

/** @public */
export type AuthFlowType = 'auth-code' | 'device-auth';
/** @public */
export const ALL_AUTH_FLOW_TYPES: readonly AuthFlowType[] = Object.freeze([
  'auth-code',
  'device-auth',
]);

/**
 * Information that the application needs to show to users when using the
 * Device Authorization flow.
 *
 * @public
 */
export interface DeviceFlowInformation {
  verificationUrl: string;
  userCode: string;
}

/** @public */
export type OpenBrowserReturnType =
  | void
  | undefined
  | (TypedEventEmitter<{
      exit(exitCode: number): void;
      error(err: unknown): void;
    }> & {
      spawnargs?: string[];
    });

/** @public */
export interface OpenBrowserOptions {
  /**
   * The URL to open the browser with.
   */
  url: string;

  /**
   * A signal that is aborted when the user or the driver abort
   * an authentication attempt.
   */
  signal: AbortSignal;
}

/** @public */
export interface MongoDBOIDCPluginOptions {
  /**
   * A local URL to listen on. If this is not provided, a default URL
   * standardized for MongoDB applications is used.
   *
   * This is only used when the Authorization Code flow is enabled,
   * and when it is possible to open a browser.
   */
  redirectURI?: string;

  /**
   * A function that opens an URL in a browser window. If this is `false`,
   * then all flows involving automatic browser operation (currently
   * Authorization Code flow) are disabled.
   *
   * If a `{ command: string }` object is provided, `command` will be spawned
   * inside a shell and receive the target URL as an argument. If `abortable`
   * is set, then a possible AbortSignal will be passed on and the child
   * process will be killed once that is reached. (This does not typically
   * make sense for GUI browsers, but can for command-line browsers.)
   *
   * If this option is missing or undefined, the default behavior is to use
   * `shell.openExternal()` if this is running inside of electron, and
   * the `open` package otherwise.
   */
  openBrowser?:
    | undefined
    | false
    | { command: string; abortable?: boolean }
    | ((options: OpenBrowserOptions) => Promise<OpenBrowserReturnType>);

  /**
   * The maximum time that the plugin waits for an opened browser to access
   * the URL that was passed to it, in milliseconds. The default is 10 seconds.
   * Passing a value of zero will disable the timeout altogether.
   */
  openBrowserTimeout?: number;

  /**
   * A callback to provide users with the information required to operate
   * the Device Authorization flow.
   */
  notifyDeviceFlow?: (
    information: DeviceFlowInformation
  ) => Promise<void> | void;

  /**
   * Restrict possible OIDC authorization flows to a subset.
   *
   * The default value is `['auth-code']`, i.e. the Device Authorization Grant
   * flow is not enabled by default and needs to be enabled explicitly.
   *
   * Order of the entries is not relevant. The Authorization Code Flow always
   * takes precedence over the Device Authorization Grant flow.
   *
   * This can either be a static list of supported flows or a function which
   * returns such a list. In the latter case, the function will be called
   * for each authentication attempt. The AbortSignal argument can be used
   * to get insight into when the auth attempt is being aborted, by the
   * driver or through some other means. (For example, this callback
   * could be used to inform a user about the fact that re-authentication
   * is required, and reject if they decline to do so.)
   */
  allowedFlows?:
    | AuthFlowType[]
    | ((options: {
        signal: AbortSignal;
      }) => Promise<AuthFlowType[]> | AuthFlowType[]);

  /**
   * An optional EventEmitter that can be used for recording log events.
   */
  logger?: TypedEventEmitter<MongoDBOIDCLogEventsMap>;

  /**
   * An AbortSignal that can be used to explicitly cancel authentication
   * attempts, for example if a user intentionally aborts a connection
   * attempt.
   *
   * Note that the driver also registers its own AbortSignal with individual
   * authentication attempts in order to enforce a timeout, which has the
   * same effect for authentication attempts from that driver MongoClient
   * instance (but does not prevent other MongoClients from using this
   * plugin instance to authenticate).
   */
  signal?: OIDCAbortSignal;

  /**
   * A custom handler for providing HTTP responses for requests to the
   * redirect HTTP server used in the Authorization Code Flow.
   *
   * The default handler serves simple text/plain messages.
   */
  redirectServerRequestHandler?: RedirectServerRequestHandler;

  /**
   * A serialized representation of a previous plugin instance's state
   * as returned by `.serialize()`.
   *
   * This option should only be passed if it comes from a trusted source,
   * since it contains access tokens that will be sent to MongoDB servers.
   */
  serializedState?: string;

  /**
   * If set to true, creating the plugin will throw an exception when
   * `serializedState` is provided but cannot be deserialized.
   * If set to false, invalid serialized state will result in a log
   * message being emitted but otherwise be ignored.
   */
  throwOnIncompatibleSerializedState?: boolean;

  /**
   * Provide custom HTTP options for individual HTTP calls.
   *
   * @deprecated Use a custom `fetch` function instead.
   */
  customHttpOptions?:
    | HttpOptions
    | ((url: string, options: Readonly<HttpOptions>) => HttpOptions);

  /**
   * Provide a custom `fetch` function to be used for HTTP calls.
   *
   * Any API that is compatible with the web `fetch` API can be used here.
   */
  customFetch?: (url: string, options: Readonly<unknown>) => Promise<Response>;

  /**
   * Pass ID tokens in place of access tokens. For debugging/working around
   * broken identity providers.
   */
  passIdTokenAsAccessToken?: boolean;

  /**
   * Skip the nonce parameter in the Authorization Code request. This could
   * be used to work with providers that don't support the nonce parameter.
   *
   * Default is `false`.
   */
  skipNonceInAuthCodeRequest?: boolean;
}

/** @public */
export interface MongoDBOIDCPluginMongoClientOptions {
  readonly authMechanismProperties: {
    readonly OIDC_HUMAN_CALLBACK: OIDCCallbackFunction;
  };
}

/** @public */
export interface MongoDBOIDCPlugin {
  /**
   * A subset of MongoClientOptions that need to be set in order
   * for the MongoClient to an instance of this plugin.
   *
   * This object should be deep-merged with other, pre-existing
   * MongoClient driver options.
   *
   * @public
   */
  readonly mongoClientOptions: MongoDBOIDCPluginMongoClientOptions;

  /**
   * The logger instance passed in the options, or a default one otherwise.
   */
  readonly logger: TypedEventEmitter<MongoDBOIDCLogEventsMap>;

  /**
   * Create a serialized representation of this plugin's state. The result
   * can be stored and be later passed to new plugin instances to make
   * that instance behave as a resumed version of this instance.
   *
   * Be aware that this string contains OIDC tokens in plaintext! Do not
   * store it without appropriate security mechanisms in place.
   */
  serialize(): Promise<string>;

  /**
   * Destroy this plugin instance. Currently, this only clears timers
   * for automatic token refreshing.
   */
  destroy(): Promise<void>;
}

/** @internal */
export const publicPluginToInternalPluginMap_DoNotUseOutsideOfTests =
  new WeakMap<MongoDBOIDCPlugin, MongoDBOIDCPluginImpl>();

/**
 * Create a new OIDC plugin instance that can be passed to the Node.js MongoDB
 * driver's MongoClientOptions struct.
 *
 * This plugin instance can be passed to multiple MongoClient instances.
 * It caches credentials based on cluster OIDC metadata.
 * Do *not* pass the plugin instance to multiple MongoClient instances when the
 * MongoDB deployments they are connecting to do not share a trust relationship
 * since an untrusted server may be able to advertise malicious OIDC metadata
 * (this restriction may be lifted in a future version of this library).
 * Do *not* pass the plugin instance to multiple MongoClient instances when they
 * are being used with different usernames (user principals), in the connection
 * string or in the MongoClient options.
 *
 * @public
 */
export function createMongoDBOIDCPlugin(
  options: Readonly<MongoDBOIDCPluginOptions>
): MongoDBOIDCPlugin {
  const plugin = new MongoDBOIDCPluginImpl({ ...options });
  const publicPlugin: MongoDBOIDCPlugin = {
    mongoClientOptions: plugin.mongoClientOptions,
    logger: plugin.logger,
    serialize: plugin.serialize.bind(plugin),
    destroy: plugin.destroy.bind(plugin),
  };
  publicPluginToInternalPluginMap_DoNotUseOutsideOfTests.set(
    publicPlugin,
    plugin
  );
  return publicPlugin;
}

/** @internal */
export const kDefaultOpenBrowserTimeout = 20_000;

/** @public */
export type RedirectServerRequestInfo = {
  /** The incoming HTTP request. */
  req: HttpIncomingMessage;
  /** The outgoing HTTP response. */
  res: HttpServerResponse;
  /** The suggested HTTP status code. For unknown-url, this is 404. */
  status: number;
} & (
  | {
      result: 'redirecting';
      location: string;
    }
  | {
      result: 'rejected';
      /** Error information reported by the IdP as defined in RFC6749 section 4.1.2.1 */
      error?: string;
      /** Error information reported by the IdP as defined in RFC6749 section 4.1.2.1 */
      errorDescription?: string;
      /** Error information reported by the IdP as defined in RFC6749 section 4.1.2.1 */
      errorURI?: string;
    }
  | {
      result: 'accepted';
    }
  | {
      result: 'unknown-url';
    }
);

/** @public */
export type RedirectServerRequestHandler = (
  data: RedirectServerRequestInfo
) => void;
