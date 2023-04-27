import type {
  MongoDBOIDCLogEventsMap,
  OIDCAbortSignal,
  OIDCClientInfo,
  OIDCMechanismServerStep1,
  OIDCRequestTokenResult,
  TypedEventEmitter,
} from './types';
import { MongoDBOIDCError } from './types';
import {
  AbortController,
  errorString,
  normalizeObject,
  throwIfAborted,
  timeoutSignal,
  withAbortCheck,
  withLock,
} from './util';
import type { Client, BaseClient } from 'openid-client';
import { TokenSet } from 'openid-client';
import { Issuer, generators } from 'openid-client';
import { RFC8252HTTPServer } from './rfc-8252-http-server';
import { promisify } from 'util';
import { randomBytes } from 'crypto';
import { EventEmitter } from 'events';
import type {
  AuthFlowType,
  DeviceFlowInformation,
  MongoDBOIDCPlugin,
  MongoDBOIDCPluginOptions,
  OpenBrowserOptions,
  OpenBrowserReturnType,
} from './api';
import { kDefaultOpenBrowserTimeout } from './api';
import { spawn } from 'child_process';

/** @internal */
interface UserOIDCAuthState {
  // The information that the driver forwarded to us from the server
  // about the OIDC Identity Provider config.
  serverOIDCMetadata: OIDCMechanismServerStep1;
  // A Promise that resolves when the current authentication attempt
  // is finished, if there is one at the moment.
  currentAuthAttempt: Promise<OIDCRequestTokenResult> | null;
  // The last set of OIDC tokens we have received together with a
  // callback to refresh it and the client used to obtain it, if available.
  currentTokenSet: {
    set: TokenSet;
    tryRefresh(): Promise<boolean>;
  } | null;
  // A cached Client instance that uses the issuer metadata as discovered
  // through serverOIDCMetadata.
  client?: Client;
}

// eslint-disable-next-line @typescript-eslint/consistent-type-imports
let _electron: typeof import('electron') | 'cannot-require' | undefined =
  undefined;
async function getDefaultOpenBrowser(): Promise<
  (options: OpenBrowserOptions) => Promise<OpenBrowserReturnType>
> {
  // If running electron, use electron.shell.openExternal() by default
  // to open a browser.
  if (process.versions.electron && _electron !== 'cannot-require') {
    try {
      _electron ??= await import('electron');
      return ({ url }) =>
        // eslint-disable-next-line @typescript-eslint/consistent-type-imports
        (_electron as typeof import('electron')).shell.openExternal(url);
    } catch {
      _electron = 'cannot-require';
    }
  }
  // Otherwise, use open() from npm.
  return async ({ url }) => {
    // 'open' 9.x+ is ESM-only.
    const open = (await import('open')).default;
    const child = await open(url);
    child.unref();
    return child;
  };
}

/** @internal Exported for testing only */
export function automaticRefreshTimeoutMS(
  tokenSet: Pick<TokenSet, 'refresh_token' | 'expires_in'>
): number | undefined {
  // If the tokens expire in more than 1 minute, automatically register
  // a refresh handler. (They should not expire in less; however,
  // if we didn't handle that case, we'd run the risk of refreshing very
  // frequently.) Refresh the token 5 minutes before expiration or
  // halfway between now and the expiration time, whichever comes later
  // (expires in 1 hour -> refresh in 55 min, expires in 5 min -> refresh in 2.5 min).
  if (
    tokenSet.refresh_token &&
    tokenSet.expires_in &&
    tokenSet.expires_in >= 60 /* 1 minute */
  ) {
    return (
      Math.max(
        tokenSet.expires_in - 300 /* 5 minutes */,
        tokenSet.expires_in / 2
      ) * 1000
    );
  }
}

const kEnableFallback = Symbol.for('@@mdb.oidcplugin.kEnableFallback');

function allowFallbackIfFailed<T>(promise: Promise<T>): Promise<T> {
  return promise.catch((err) => {
    // Tell the outer logic here to fallback to device auth flow if it is
    // available if any of the steps above failed.
    if (Object.isExtensible(err)) {
      err[kEnableFallback] = true;
    }
    throw err;
  });
}

/** @internal */
export class MongoDBOIDCPluginImpl implements MongoDBOIDCPlugin {
  private readonly options: Readonly<MongoDBOIDCPluginOptions>;
  public readonly logger: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
  private readonly mapUserToAuthState = new Map<string, UserOIDCAuthState>();
  public readonly mongoClientOptions: MongoDBOIDCPlugin['mongoClientOptions'];
  private readonly timers: {
    // Only for testing
    setTimeout: typeof setTimeout;
    clearTimeout: typeof clearTimeout;
  };

  constructor(options: Readonly<MongoDBOIDCPluginOptions>) {
    this.options = options;
    this.logger = options.logger ?? new EventEmitter();
    this.mongoClientOptions = {
      authMechanismProperties: {
        REQUEST_TOKEN_CALLBACK: this.requestToken.bind(this),
        REFRESH_TOKEN_CALLBACK: this.requestToken.bind(this),
      },
    };
    this.timers = { setTimeout, clearTimeout };
    if (options.serializedState) {
      this._deserialize(options.serializedState);
    }
  }

  private _deserialize(serialized: string) {
    try {
      let original: ReturnType<typeof this._serialize>;
      try {
        original = JSON.parse(
          Buffer.from(serialized, 'base64').toString('utf8')
        );
      } catch (err) {
        throw new Error(
          `Stored OIDC data could not be deserialized: ${
            (err as Error).message
          }`
        );
      }

      if (original.oidcPluginStateVersion !== 0) {
        throw new Error(
          `Stored OIDC data could not be deserialized because of a version mismatch (got ${JSON.stringify(
            original.oidcPluginStateVersion
          )}, expected 0)`
        );
      }

      for (const [key, serializedState] of original.state) {
        const state = {
          serverOIDCMetadata: { ...serializedState.serverOIDCMetadata },
          currentAuthAttempt: null,
          currentTokenSet: null,
        };
        this.updateStateWithTokenSet(
          state,
          new TokenSet(serializedState.currentTokenSet.set)
        );
        this.mapUserToAuthState.set(key, state);
      }
    } catch (err) {
      this.logger.emit('mongodb-oidc-plugin:deserialization-failed', {
        error: (err as Error).message,
      });
      // It's not necessary to throw by default here since failure to
      // deserialize previous state means that, at worst, users will have
      // to re-authenticate.
      if (this.options.throwOnIncompatibleSerializedState) throw err;
    }
  }

  // Separate method so we can re-use the inferred return type in _deserialize()
  private _serialize() {
    return {
      oidcPluginStateVersion: 0,
      state: [...this.mapUserToAuthState]
        .filter(([, state]) => !!state.currentTokenSet)
        .map(([key, state]) => {
          return [
            key,
            {
              serverOIDCMetadata: { ...state.serverOIDCMetadata },
              currentTokenSet: {
                set: { ...state.currentTokenSet?.set },
              },
            },
          ] as const;
        }),
    } as const;
  }

  public serialize(): Promise<string> {
    // Wrap the result using JS-to-JSON-to-UTF8-to-Base64. We could probably
    // omit the base64 encoding, but this makes it clearer that it's an opaque
    // value that's not intended to be inspected or modified.
    return Promise.resolve(
      Buffer.from(JSON.stringify(this._serialize()), 'utf8').toString('base64')
    );
  }

  // Is this flow supported and allowed?
  private isFlowAllowed(flow: AuthFlowType): boolean {
    if (this.options.allowedFlows?.includes(flow) === false) return false;
    if (flow === 'auth-code' && this.options.openBrowser === false)
      return false;
    if (flow === 'device-auth' && !this.options.notifyDeviceFlow) return false;
    return true;
  }

  // Return the current state for a given [server, username] configuration,
  // or create a new one if none exists.
  private getAuthState(
    serverMetadata: OIDCMechanismServerStep1,
    principalName: string | null | undefined
  ): UserOIDCAuthState {
    if (!serverMetadata.clientId) {
      throw new MongoDBOIDCError(
        'No clientId passed in server OIDC metadata object'
      );
    }
    principalName ??= null;

    const key = JSON.stringify({
      // If any part of the server metadata changes, we should probably use
      // a new cache entry.
      ...normalizeObject(serverMetadata),
      principalName,
    });
    const existing = this.mapUserToAuthState.get(key);
    if (existing) return existing;
    const newState: UserOIDCAuthState = {
      serverOIDCMetadata: serverMetadata,
      currentAuthAttempt: null,
      currentTokenSet: null,
    };
    this.mapUserToAuthState.set(key, newState);
    return newState;
  }

  private getRedirectURI(): string {
    if (!this.isFlowAllowed('auth-code')) return '';
    // TODO(MONGOSH-1394): Properly standardize a port
    return this.options.redirectURI ?? 'http://localhost:27097/redirect';
  }

  private async getOIDCClient(state: UserOIDCAuthState): Promise<{
    scope: string;
    issuer: Issuer;
    client: BaseClient;
  }> {
    const serverMetadata = state.serverOIDCMetadata;
    const scope = [
      ...new Set([
        'openid',
        'offline_access',
        ...(serverMetadata.requestScopes ?? []),
      ]),
    ].join(' ');

    if (state.client) {
      return {
        scope,
        issuer: state.client.issuer,
        client: state.client,
      };
    }

    const issuer = await Issuer.discover(serverMetadata.issuer);
    const client = new issuer.Client({
      client_id: serverMetadata.clientId,
      redirect_uris: [this.getRedirectURI()],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    });
    state.client = client;

    return {
      scope,
      issuer,
      client,
    };
  }

  private async openBrowser(
    options: OpenBrowserOptions
  ): Promise<OpenBrowserReturnType> {
    // Consistency check: options.url is a valid URL.
    new URL(options.url);
    this.logger.emit('mongodb-oidc-plugin:open-browser', {
      customOpener: !!this.options.openBrowser,
    });
    if (this.options.openBrowser === false) {
      // We should never really get to this point
      throw new Error('Cannot open browser if `openBrowser` is false');
    }
    if (typeof this.options.openBrowser === 'function') {
      return await this.options.openBrowser(options);
    }
    if (this.options.openBrowser === undefined) {
      const defaultOpener = await getDefaultOpenBrowser();
      return await defaultOpener(options);
    }
    if (typeof this.options.openBrowser?.command === 'string') {
      const child = spawn(this.options.openBrowser.command, [options.url], {
        shell: true,
        stdio: 'ignore',
        detached: true,
        signal: this.options.openBrowser.abortable ? options.signal : undefined,
      });
      child.unref();
      return child;
    }
    throw new Error('Unknown format for `openBrowser`');
  }

  private async notifyDeviceFlow(
    deviceFlowInformation: DeviceFlowInformation
  ): Promise<void> {
    if (!this.options.notifyDeviceFlow) {
      // Should never happen.
      throw new Error('notifyDeviceFlow() requested but not provided');
    }
    this.logger.emit('mongodb-oidc-plugin:notify-device-flow');
    await this.options.notifyDeviceFlow(deviceFlowInformation);
  }

  private updateStateWithTokenSet(
    state: UserOIDCAuthState,
    tokenSet: TokenSet
  ) {
    const timerDuration = automaticRefreshTimeoutMS(tokenSet);
    let timer = timerDuration
      ? this.timers.setTimeout(() => void tryRefresh(), timerDuration).unref()
      : undefined;
    const tryRefresh = withLock(async () => {
      if (timer) {
        this.timers.clearTimeout(timer);
        timer = undefined;
      }
      // Only refresh this token set if it is the one currently
      // being used.
      if (state.currentTokenSet?.set !== tokenSet) return false;
      try {
        this.logger.emit('mongodb-oidc-plugin:refresh-started');

        const { client } = await this.getOIDCClient(state);
        const refreshedTokens = await client.refresh(tokenSet);
        // Check again to avoid race conditions.
        if (state.currentTokenSet?.set === tokenSet) {
          this.logger.emit('mongodb-oidc-plugin:refresh-succeeded');
          this.updateStateWithTokenSet(state, refreshedTokens);
          return true;
        }
      } catch (err: unknown) {
        this.logger.emit('mongodb-oidc-plugin:refresh-failed', {
          error: errorString(err),
        });
      }
      return false;
    });

    state.currentTokenSet = {
      set: tokenSet,
      tryRefresh,
    };

    this.logger.emit('mongodb-oidc-plugin:state-updated');
  }

  private verifyValidUrl(
    serverOIDCMetadata: OIDCMechanismServerStep1,
    key: keyof OIDCMechanismServerStep1
  ): void {
    // Verify that `key` refers to a valid URL. This is currently
    // *not* an error that we allow to fall back from.
    const value = serverOIDCMetadata[key];
    if (!value || typeof value !== 'string') {
      throw new MongoDBOIDCError(`'${key}' is missing`);
    } else {
      try {
        new URL(value);
      } catch {
        throw new MongoDBOIDCError(`'${key}' is invalid: ${value}}`);
      }
    }
  }

  private async authorizationCodeFlow(
    state: UserOIDCAuthState,
    signal: AbortSignal
  ): Promise<void> {
    this.verifyValidUrl(state.serverOIDCMetadata, 'issuer');

    const { scope, client } = await this.getOIDCClient(state);

    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);

    const oidcStateParam = (await promisify(randomBytes)(16)).toString('hex');
    const server = new RFC8252HTTPServer({
      redirectUrl: this.getRedirectURI(),
      logger: this.logger,
      redirectServerRequestHandler: this.options.redirectServerRequestHandler,
      oidcStateParam,
    });
    let paramsUrl = '';

    try {
      await withAbortCheck(signal, async ({ signalCheck, signalPromise }) => {
        // We mark the operations that we want to allow to result in a fallback
        // to potentially less secure flows explicitly.
        // Specifically, we only do so if we cannot open a local HTTP server
        // or a local browser. Once we have done that, we do not want to fall
        // back to another flow anymore, and any error from there on is most likely
        // a genuine authentication error.
        await Promise.race([
          allowFallbackIfFailed(server.listen()),
          signalPromise,
        ]);

        const authCodeFlowUrl = client.authorizationUrl({
          scope,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: oidcStateParam,
        });
        const { localUrl, onAccessed: onLocalUrlAccessed } =
          await server.addRedirect(authCodeFlowUrl);

        signalCheck();

        // Handle errors from opening a browser but do not await the Promise
        // in case it only resolves when the browser exits (which is the case
        // for the default `open` handler).
        const browserStatePromise = allowFallbackIfFailed(
          new Promise<never>((resolve, reject) => {
            this.openBrowser({ url: localUrl, signal })
              .then((browserHandle) => {
                browserHandle?.once('error', (err) => reject(err));
                browserHandle?.once('exit', (code) => {
                  if (code !== 0)
                    reject(
                      new MongoDBOIDCError(
                        `Opening browser failed with exit code ${code}`
                      )
                    );
                });
              })
              .catch(reject);
          })
        );

        const timeout: Promise<never> = allowFallbackIfFailed(
          new Promise((resolve, reject) => {
            if (this.options.openBrowserTimeout !== 0) {
              setTimeout(
                reject,
                this.options.openBrowserTimeout ?? kDefaultOpenBrowserTimeout,
                new MongoDBOIDCError('Opening browser timed out')
              ).unref();
            }
          })
        );

        browserStatePromise.catch(() => {
          /* squelch UnhandledPromiseRejectionWarning */
        });
        timeout.catch(() => {
          /* ditto */
        });
        await Promise.race([
          onLocalUrlAccessed,
          timeout,
          browserStatePromise,
          signalPromise,
        ]);

        paramsUrl = await server.waitForOIDCParamsAndClose({ signal });
      });
    } finally {
      await server.close();
    }

    const params = client.callbackParams(paramsUrl);
    const tokenSet = await client.callback(this.getRedirectURI(), params, {
      code_verifier: codeVerifier,
      state: oidcStateParam,
    });
    this.updateStateWithTokenSet(state, tokenSet);
  }

  private async deviceAuthorizationFlow(
    state: UserOIDCAuthState,
    signal: AbortSignal
  ): Promise<void> {
    this.verifyValidUrl(state.serverOIDCMetadata, 'issuer');

    const { scope, client } = await this.getOIDCClient(state);

    await withAbortCheck(signal, async ({ signalCheck, signalPromise }) => {
      const deviceFlowHandle = await Promise.race([
        client.deviceAuthorization({
          client_id: client.metadata.client_id,
          scope,
        }),
        signalPromise,
      ]);

      signalCheck();
      await this.notifyDeviceFlow({
        userCode: deviceFlowHandle.user_code,
        verificationUrl: deviceFlowHandle.verification_uri,
      });

      const tokenSet = await deviceFlowHandle.poll({ signal });
      this.updateStateWithTokenSet(state, tokenSet);
    });
  }

  private async initiateAuthAttempt(
    state: UserOIDCAuthState,
    driverAbortSignal?: OIDCAbortSignal
  ): Promise<OIDCRequestTokenResult> {
    throwIfAborted(this.options.signal);
    throwIfAborted(driverAbortSignal);

    const combinedAbortController = new AbortController();
    const optionsAbortCb = () => {
      // @ts-expect-error TS doesn't understand .abort(reason)
      combinedAbortController.abort(this.options.signal.reason);
    };
    const driverAbortCb = () => {
      // @ts-expect-error TS doesn't understand .abort(reason)
      combinedAbortController.abort(driverAbortSignal.reason);
    };
    this.options.signal?.addEventListener('abort', optionsAbortCb);
    driverAbortSignal?.addEventListener('abort', driverAbortCb);
    const signal = combinedAbortController.signal;

    try {
      get_tokens: {
        if ((state.currentTokenSet?.set?.expires_in ?? 0) > 5 * 60) {
          this.logger.emit('mongodb-oidc-plugin:skip-auth-attempt', {
            reason: 'not-expired',
          });
          break get_tokens;
        }
        if (await state.currentTokenSet?.tryRefresh?.()) {
          this.logger.emit('mongodb-oidc-plugin:skip-auth-attempt', {
            reason: 'refresh-succeeded',
          });
          break get_tokens;
        }
        state.currentTokenSet = null;
        let error;
        if (this.isFlowAllowed('auth-code')) {
          try {
            this.logger.emit('mongodb-oidc-plugin:auth-attempt-started', {
              flow: 'auth-code',
            });
            await this.authorizationCodeFlow(state, signal);
            this.logger.emit('mongodb-oidc-plugin:auth-attempt-succeeded');
            break get_tokens;
          } catch (err: unknown) {
            error = err;
            this.logger.emit('mongodb-oidc-plugin:auth-attempt-failed', {
              error: errorString(err),
            });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            if (!(err as any)?.[kEnableFallback]) throw err;
          }
        }
        if (this.isFlowAllowed('device-auth')) {
          try {
            this.logger.emit('mongodb-oidc-plugin:auth-attempt-started', {
              flow: 'device-auth',
            });
            await this.deviceAuthorizationFlow(state, signal);
            this.logger.emit('mongodb-oidc-plugin:auth-attempt-succeeded');
            break get_tokens;
          } catch (err: unknown) {
            this.logger.emit('mongodb-oidc-plugin:auth-attempt-failed', {
              error: errorString(err),
            });
            throw err;
          }
        }
        if (error) throw error;
      }

      if (!state.currentTokenSet?.set?.access_token) {
        throw new MongoDBOIDCError('Could not retrieve valid access token');
      }
    } catch (err: unknown) {
      this.logger.emit('mongodb-oidc-plugin:auth-failed', {
        error: errorString(err),
      });
      throw err;
    } finally {
      this.options.signal?.removeEventListener('abort', optionsAbortCb);
      driverAbortSignal?.removeEventListener('abort', driverAbortCb);
    }

    this.logger.emit('mongodb-oidc-plugin:auth-succeeded', {
      hasRefreshToken: !!state.currentTokenSet.set.refresh_token,
      expiresAt: state.currentTokenSet.set.expires_at
        ? new Date(state.currentTokenSet.set.expires_at * 1000).toISOString()
        : null,
    });

    return {
      accessToken: state.currentTokenSet.set.access_token,
      refreshToken: state.currentTokenSet.set.refresh_token,
      // Passing `expiresInSeconds: 0` results in the driver not caching the token.
      // We perform our own caching here inside the plugin, so interactions with the
      // cache of the driver are not really required or necessarily helpful.
      // The driver cache has a finer cache key (host address instead of clientId),
      // so may require more authentication attempts, and is global,
      // not per-MongoClient.
      // It probably would be fine to pass in the actual expiration time here, but
      // there seem to be no benefits to doing so.
      expiresInSeconds: 0,
    };
  }

  public async requestToken(
    clientInfo: OIDCClientInfo,
    serverMetadata: OIDCMechanismServerStep1
  ): Promise<OIDCRequestTokenResult> {
    const state = this.getAuthState(serverMetadata, clientInfo.principalName);

    if (state.currentAuthAttempt) {
      return await state.currentAuthAttempt;
    }

    // The currently plan is for the 6.x driver (which may drop support
    // for Node.js 14.x) to pass in an actual AbortSignal here. For
    // compatibility with the 5.x driver/AbortSignal-less-Node.js, we accept
    // a timeout in milliseconds as well.
    const driverAbortSignal =
      clientInfo.timeoutContext ??
      (clientInfo.timeoutSeconds
        ? timeoutSignal(clientInfo.timeoutSeconds * 1000)
        : undefined);

    const newAuthAttempt = this.initiateAuthAttempt(state, driverAbortSignal);
    state.currentAuthAttempt = newAuthAttempt;
    newAuthAttempt.finally(() => {
      if (state.currentAuthAttempt === newAuthAttempt)
        state.currentAuthAttempt = null;
    });
    return newAuthAttempt;
  }
}
