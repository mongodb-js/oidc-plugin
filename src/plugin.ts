import type {
  MongoDBOIDCLogEventsMap,
  OIDCAbortSignal,
  OIDCCallbackContext,
  IdPServerInfo,
  IdPServerResponse,
  TypedEventEmitter,
} from './types';
import { MongoDBOIDCError } from './types';
import {
  AbortController,
  errorString,
  normalizeObject,
  throwIfAborted,
  timeoutSignal,
  validateSecureHTTPUrl,
  withAbortCheck,
  withLock,
} from './util';
import type { Client, BaseClient, IdTokenClaims } from 'openid-client';
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

// The `sub` and `aud` claims in the ID token of the last-received
// TokenSet, if any.
// 'no-id-token' means that the previous token set contained no ID token
type LastIdTokenClaims =
  | (Pick<IdTokenClaims, 'aud' | 'sub'> & { noIdToken?: never })
  | { noIdToken: true };

interface UserOIDCAuthState {
  // The information that the driver forwarded to us from the server
  // about the OIDC Identity Provider config.
  serverOIDCMetadata: IdPServerInfo;
  // A Promise that resolves when the current authentication attempt
  // is finished, if there is one at the moment.
  currentAuthAttempt: Promise<IdPServerResponse> | null;
  // The last set of OIDC tokens we have received together with a
  // callback to refresh it and the client used to obtain it, if available.
  currentTokenSet: {
    set: TokenSet;
    tryRefresh(): Promise<boolean>;
  } | null;
  // A timer attached to this state that automatically calls
  // currentTokenSet.tryRefresh() before the token expires.
  timer?: ReturnType<typeof setTimeout>;
  lastIdTokenClaims?: LastIdTokenClaims;
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
    // 'open' 9.x+ is ESM-only. However, TypeScript transpiles
    // the `await import()` here to `require()`, which fails to load
    // the package at runtime. We cannot use one of the typical workarounds
    // for loading ESM packages unconditionally, because we need to be
    // able to webpack this file (e.g. in Compass), which means that we
    // need to use imports with constant string literal arguments.
    // eslint-disable-next-line @typescript-eslint/consistent-type-imports
    let open: typeof import('open').default;
    try {
      open = (await import('open')).default;
    } catch (err: unknown) {
      if (
        err &&
        typeof err === 'object' &&
        'code' in err &&
        err.code === 'ERR_REQUIRE_ESM' &&
        typeof __webpack_require__ === 'undefined'
      ) {
        // This means that the import() above was transpiled to require()
        // and that that require() called failed because it saw actual on-disk ESM.
        // In this case, it should be safe to use eval'ed import().
        open = (await eval("import('open')")).default;
      } else {
        throw err;
      }
    }
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
  private readonly mapIdpToAuthState = new Map<string, UserOIDCAuthState>();
  public readonly mongoClientOptions: MongoDBOIDCPlugin['mongoClientOptions'];
  private readonly timers: {
    // Only for testing
    setTimeout: typeof setTimeout;
    clearTimeout: typeof clearTimeout;
  };
  private destroyed = false;

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
        throw new MongoDBOIDCError(
          `Stored OIDC data could not be deserialized: ${
            (err as Error).message
          }`
        );
      }

      if (original.oidcPluginStateVersion !== 0) {
        throw new MongoDBOIDCError(
          `Stored OIDC data could not be deserialized because of a version mismatch (got ${JSON.stringify(
            original.oidcPluginStateVersion
          )}, expected 0)`
        );
      }

      for (const [key, serializedState] of original.state) {
        const state: UserOIDCAuthState = {
          serverOIDCMetadata: { ...serializedState.serverOIDCMetadata },
          currentAuthAttempt: null,
          currentTokenSet: null,
          lastIdTokenClaims: serializedState.lastIdTokenClaims
            ? { ...serializedState.lastIdTokenClaims }
            : undefined,
        };
        this.updateStateWithTokenSet(
          state,
          new TokenSet(serializedState.currentTokenSet.set)
        );
        this.mapIdpToAuthState.set(key, state);
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
      state: [...this.mapIdpToAuthState]
        .filter(([, state]) => !!state.currentTokenSet)
        .map(([key, state]) => {
          return [
            key,
            {
              serverOIDCMetadata: { ...state.serverOIDCMetadata },
              currentTokenSet: {
                set: { ...state.currentTokenSet?.set },
              },
              lastIdTokenClaims: state.lastIdTokenClaims
                ? { ...state.lastIdTokenClaims }
                : undefined,
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
  private async getAllowedFlows({
    signal,
  }: {
    signal: AbortSignal;
  }): Promise<AuthFlowType[]> {
    const flowList = new Set<AuthFlowType>(
      typeof this.options.allowedFlows === 'function'
        ? await this.options.allowedFlows({ signal })
        : this.options.allowedFlows ?? ['auth-code']
    );
    // Remove flows from the set whose prerequisites aren't fulfilled.
    if (this.options.openBrowser === false) flowList.delete('auth-code');
    if (!this.options.notifyDeviceFlow) flowList.delete('device-auth');
    return [...flowList];
  }

  // Return the current state for a given [server, username] configuration,
  // or create a new one if none exists.
  private getAuthState(serverMetadata: IdPServerInfo): UserOIDCAuthState {
    if (!serverMetadata.issuer || typeof serverMetadata.issuer !== 'string') {
      throw new MongoDBOIDCError(`'issuer' is missing`);
    }
    validateSecureHTTPUrl(serverMetadata.issuer, 'issuer');

    if (!serverMetadata.clientId) {
      throw new MongoDBOIDCError(
        'No clientId passed in server OIDC metadata object'
      );
    }

    const key = JSON.stringify({
      // If any part of the server metadata changes, we should probably use
      // a new cache entry.
      ...normalizeObject(serverMetadata),
    });
    const existing = this.mapIdpToAuthState.get(key);
    if (existing) return existing;
    const newState: UserOIDCAuthState = {
      serverOIDCMetadata: serverMetadata,
      currentAuthAttempt: null,
      currentTokenSet: null,
    };
    this.mapIdpToAuthState.set(key, newState);
    return newState;
  }

  private async getOIDCClient(
    state: UserOIDCAuthState,
    redirectURIs?: string[]
  ): Promise<{
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
        // need to re-create Client here because redirect_uris might
        // differ between calls to this method
        client: new state.client.issuer.Client({
          ...state.client.metadata,
          redirect_uris: redirectURIs,
        }),
      };
    }

    validateSecureHTTPUrl(serverMetadata.issuer, 'issuer');
    const issuer = await Issuer.discover(serverMetadata.issuer);
    validateSecureHTTPUrl(
      issuer.metadata.authorization_endpoint,
      'authorization_endpoint'
    );
    validateSecureHTTPUrl(
      issuer.metadata.device_authorization_endpoint,
      'device_authorization_endpoint'
    );
    validateSecureHTTPUrl(issuer.metadata.token_endpoint, 'token_endpoint');
    validateSecureHTTPUrl(issuer.metadata.jwks_uri, 'jwks_uri');
    const client = new issuer.Client({
      client_id: serverMetadata.clientId,
      redirect_uris: redirectURIs,
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
    // Consistency check: options.url is a valid URL and does not contain
    // characters that would have special semantics when passed to a
    // child process spawned with `shell: true`.
    // That might not be true for the URL we got from the IdP, but since we
    // wrap it in our own redirect first anyway, we can guarantee that the
    // URL has this format.
    new URL(options.url);
    if (!/^[a-zA-Z0-9%/:;_.,=@-]+$/.test(options.url)) {
      throw new MongoDBOIDCError(
        `Unexpected format for internally generated URL: '${options.url}'`
      );
    }
    this.logger.emit('mongodb-oidc-plugin:open-browser', {
      customOpener: !!this.options.openBrowser,
    });
    if (this.options.openBrowser === false) {
      // We should never really get to this point
      throw new MongoDBOIDCError(
        'Cannot open browser if `openBrowser` is false'
      );
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
    throw new MongoDBOIDCError('Unknown format for `openBrowser`');
  }

  private async notifyDeviceFlow(
    deviceFlowInformation: DeviceFlowInformation
  ): Promise<void> {
    validateSecureHTTPUrl(
      deviceFlowInformation.verificationUrl,
      'verificationUrl'
    );
    if (!this.options.notifyDeviceFlow) {
      // Should never happen.
      throw new MongoDBOIDCError(
        'notifyDeviceFlow() requested but not provided'
      );
    }
    this.logger.emit('mongodb-oidc-plugin:notify-device-flow');
    await this.options.notifyDeviceFlow(deviceFlowInformation);
  }

  private updateStateWithTokenSet(
    state: UserOIDCAuthState,
    tokenSet: TokenSet
  ) {
    // We intend to be able to pass plugin instances to multiple MongoClient
    // instances that are connecting to the same MongoDB endpoint.
    // We need to prevent a scenario in which a requestToken callback is called
    // for client A, the token expires before it is requested again by client A,
    // then the plugin is passed to client B which requests a token, and we
    // receive mismatching tokens for different users or different audiences.
    if (
      !tokenSet.id_token &&
      state.lastIdTokenClaims &&
      !state.lastIdTokenClaims.noIdToken
    ) {
      throw new MongoDBOIDCError(
        `ID token expected, but not found. Expected claims: ${JSON.stringify(
          state.lastIdTokenClaims
        )}`
      );
    }

    if (
      tokenSet.id_token &&
      state.lastIdTokenClaims &&
      state.lastIdTokenClaims.noIdToken
    ) {
      throw new MongoDBOIDCError(`Unexpected ID token received.`);
    }

    if (tokenSet.id_token) {
      const idTokenClaims = tokenSet.claims();
      if (state.lastIdTokenClaims) {
        for (const claim of ['aud', 'sub'] as const) {
          const normalize = (value: string | string[]): string => {
            return JSON.stringify(
              Array.isArray(value) ? [...value].sort() : value
            );
          };
          const knownClaim = normalize(state.lastIdTokenClaims[claim]);
          const newClaim = normalize(idTokenClaims[claim]);

          if (knownClaim !== newClaim) {
            throw new MongoDBOIDCError(
              `Unexpected '${claim}' field in id token: Expected ${knownClaim}, saw ${newClaim}`
            );
          }
        }
      }
      state.lastIdTokenClaims = {
        aud: idTokenClaims.aud,
        sub: idTokenClaims.sub,
      };
    } else {
      state.lastIdTokenClaims = { noIdToken: true };
      this.logger.emit('mongodb-oidc-plugin:missing-id-token');
    }

    const timerDuration = automaticRefreshTimeoutMS(tokenSet);
    // Use `.call()` because in browsers, `setTimeout()` requires that it is called
    // without a `this` value. `.unref()` is not available in browsers either.
    if (state.timer) this.timers.clearTimeout.call(null, state.timer);
    state.timer = timerDuration
      ? this.timers.setTimeout.call(
          null,
          () => void tryRefresh(),
          timerDuration
        )
      : undefined;
    state.timer?.unref?.();
    const tryRefresh = withLock(async () => {
      if (state.timer) {
        this.timers.clearTimeout.call(null, state.timer);
        state.timer = undefined;
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

  static readonly defaultRedirectURI = 'http://localhost:27097/redirect';

  private async authorizationCodeFlow(
    state: UserOIDCAuthState,
    signal: AbortSignal
  ): Promise<void> {
    const configuredRedirectURI =
      this.options.redirectURI ?? MongoDBOIDCPluginImpl.defaultRedirectURI;

    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);

    const oidcStateParam = (await promisify(randomBytes)(16)).toString('hex');
    const server = new RFC8252HTTPServer({
      redirectUrl: configuredRedirectURI,
      logger: this.logger,
      redirectServerRequestHandler: this.options.redirectServerRequestHandler,
      oidcStateParam,
    });
    let paramsUrl = '';

    let scope!: string;
    let client!: BaseClient;
    let actualRedirectURI!: string;

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

        actualRedirectURI = server.listeningRedirectUrl as string;
        ({ scope, client } = await this.getOIDCClient(state, [
          actualRedirectURI,
        ]));

        const authCodeFlowUrl = client.authorizationUrl({
          scope,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: oidcStateParam,
        });
        validateSecureHTTPUrl(authCodeFlowUrl, 'authCodeFlowUrl');
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
                const extraErrorInfo = () =>
                  browserHandle?.spawnargs
                    ? ` (${JSON.stringify(browserHandle.spawnargs)})`
                    : '';
                browserHandle?.once('error', (err) =>
                  reject(
                    new MongoDBOIDCError(
                      `Opening browser failed with '${String(
                        err && typeof err === 'object' && 'message' in err
                          ? err.message
                          : err
                      )}'${extraErrorInfo()}`
                    )
                  )
                );
                browserHandle?.once('exit', (code) => {
                  if (code !== 0)
                    reject(
                      new MongoDBOIDCError(
                        `Opening browser failed with exit code ${code}${extraErrorInfo()}`
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
    const tokenSet = await client.callback(actualRedirectURI, params, {
      code_verifier: codeVerifier,
      state: oidcStateParam,
    });
    this.updateStateWithTokenSet(state, tokenSet);
  }

  private async deviceAuthorizationFlow(
    state: UserOIDCAuthState,
    signal: AbortSignal
  ): Promise<void> {
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
  ): Promise<IdPServerResponse> {
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
        const currentAllowedFlowSet = await this.getAllowedFlows({ signal });
        if (currentAllowedFlowSet.includes('auth-code')) {
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
        if (currentAllowedFlowSet.includes('device-auth')) {
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
    serverMetadata: IdPServerInfo,
    context: OIDCCallbackContext
  ): Promise<IdPServerResponse> {
    if (context.version !== 0) {
      throw new MongoDBOIDCError(
        `OIDC MongoDB driver protocol mismatch: unknown version ${context.version}`
      );
    }

    if (this.destroyed) {
      throw new MongoDBOIDCError(
        'This OIDC plugin instance has been destroyed and is no longer active'
      );
    }

    const state = this.getAuthState(serverMetadata);

    if (state.currentAuthAttempt) {
      return await state.currentAuthAttempt;
    }

    // The currently plan is for the 6.x driver (which may drop support
    // for Node.js 14.x) to pass in an actual AbortSignal here. For
    // compatibility with the 5.x driver/AbortSignal-less-Node.js, we accept
    // a timeout in milliseconds as well.
    const driverAbortSignal =
      context.timeoutContext ??
      (context.timeoutSeconds
        ? timeoutSignal(context.timeoutSeconds * 1000)
        : undefined);

    const newAuthAttempt = this.initiateAuthAttempt(state, driverAbortSignal);
    try {
      state.currentAuthAttempt = newAuthAttempt;
      return await newAuthAttempt;
    } finally {
      if (state.currentAuthAttempt === newAuthAttempt)
        state.currentAuthAttempt = null;
    }
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  public async destroy(): Promise<void> {
    this.destroyed = true;
    for (const [, state] of this.mapIdpToAuthState) {
      if (state.timer) {
        this.timers.clearTimeout.call(null, state.timer);
        state.timer = undefined;
      }
    }
    this.logger.emit('mongodb-oidc-plugin:destroyed');
  }
}
