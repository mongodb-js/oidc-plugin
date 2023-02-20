import { MongoDBOIDCPluginImpl } from './plugin';
import type {
  MongoDBOIDCLogEventsMap,
  OIDCAbortSignal,
  OIDCRefreshFunction,
  OIDCRequestFunction,
  TypedEventEmitter,
} from './types';

/** @public */
export type AuthFlowType = 'auth-code' | 'device-auth';

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
  | TypedEventEmitter<{
      exit(exitCode: number): void;
      error(err: unknown): void;
    }>;

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
   */
  allowedFlows?: AuthFlowType[];

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
   * authentication attempts in order to enfore a timeout, which has the
   * same effect for authentication attempts from that driver MongoClient
   * instance (but does not prevent other MongoClients from using this
   * plugin instance to authenticate).
   */
  signal?: OIDCAbortSignal;
}

/** @public */
export interface MongoDBOIDCPlugin {
  /**
   * A subset of MongoClientOptions that need to be set in order
   * for the MongoClient to an instance of this plugin.
   *
   * This object should be deep-merged with other, pre-existing
   * MongoClient driver options.
   */
  readonly mongoClientOptions: {
    readonly authMechanismProperties: {
      readonly REQUEST_TOKEN_CALLBACK: OIDCRequestFunction;
      readonly REFRESH_TOKEN_CALLBACK: OIDCRefreshFunction;
    };
  };
}

/**
 * Create a new OIDC plugin instance that can be passed to the Node.js MongoDB
 * driver's MongoClientOptions struct.
 *
 * This plugin instance can be passed to multiple MongoClient instances.
 * It caches credentials based on cluster ID and username. If no username is
 * provided when connecting to the MongoDB instance, the cache will be shared
 * across all MongoClients that use this plugin instance.
 *
 * @public
 */
export function createMongoDBOIDCPlugin(
  options: Readonly<MongoDBOIDCPluginOptions>
): MongoDBOIDCPlugin {
  const plugin = new MongoDBOIDCPluginImpl({ ...options });
  return {
    mongoClientOptions: plugin.mongoClientOptions,
  };
}

/** @internal */
export const kDefaultOpenBrowserTimeout = 10_000;
