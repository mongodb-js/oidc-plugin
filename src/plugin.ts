import type {
  MongoDBOIDCLogEventsMap,
  OIDCAbortSignal,
  OIDCMechanismServerStep1,
  OIDCRequestTokenResult,
  TypedEventEmitter,
} from './types';
import { MongoDBOIDCError } from './types';
import {
  AbortController,
  errorString,
  throwIfAborted,
  timeoutSignal,
  withAbortCheck,
} from './util';
import type {
  IssuerMetadata,
  ClientMetadata,
  TokenSet,
  Client,
} from 'openid-client';
import { Issuer, generators } from 'openid-client';
import { RFC8252HTTPServer } from './rfc-8252-http-server';
import open from 'open';
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
  // callback to refresh it, if available.
  currentTokenSet: {
    set: TokenSet;
    tryRefresh(): Promise<boolean>;
  } | null;
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
    const child = await open(url);
    child.unref();
    return child;
  };
}

const kEnableFallback = Symbol.for('@@mdb.oidcplugin.kEnableFallback');

/** @internal */
export class MongoDBOIDCPluginImpl implements MongoDBOIDCPlugin {
  private readonly options: Readonly<MongoDBOIDCPluginOptions>;
  public readonly logger: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
  private readonly mapUserToAuthState = new Map<string, UserOIDCAuthState>();
  public readonly mongoClientOptions: MongoDBOIDCPlugin['mongoClientOptions'];

  constructor(options: Readonly<MongoDBOIDCPluginOptions>) {
    this.options = options;
    this.logger = options.logger ?? new EventEmitter();
    this.mongoClientOptions = {
      authMechanismProperties: {
        REQUEST_TOKEN_CALLBACK: this.requestToken.bind(this),
        REFRESH_TOKEN_CALLBACK: this.refreshToken.bind(this),
      },
    };
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
      clientId: serverMetadata.clientId,
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

  private getInitialOIDCIssuerAndClientParams(
    serverMetadata: OIDCMechanismServerStep1
  ): {
    scope: string;
    issuerParams: IssuerMetadata;
    clientParams: ClientMetadata;
  } {
    return {
      scope: [
        ...new Set([
          'openid',
          'offline_access',
          ...(serverMetadata.requestScopes ?? []),
        ]),
      ].join(' '),
      issuerParams: {
        authorization_endpoint: serverMetadata.authorizationEndpoint,
        token_endpoint: serverMetadata.tokenEndpoint,
        device_authorization_endpoint:
          serverMetadata.deviceAuthorizationEndpoint,
        // Required by the TS definitions, but we just don't have this data
        // at this point. We re-define it later where necessary.
        issuer: '',
      },
      clientParams: {
        client_id: serverMetadata.clientId,
        client_secret: serverMetadata.clientSecret,
        redirect_uris: [this.getRedirectURI()],
        response_types: ['code'],
        // At least Okta requires this:
        token_endpoint_auth_method: serverMetadata.clientSecret
          ? 'client_secret_post'
          : 'none',
      },
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

  private storeTokenSet(
    state: UserOIDCAuthState,
    tokenSet: TokenSet,
    client: Client
  ) {
    state.currentTokenSet = {
      set: tokenSet,
      tryRefresh: async () => {
        // Only refresh this token set if it is the one currently
        // being used.
        if (state.currentTokenSet?.set !== tokenSet) return false;
        try {
          const refreshedTokens = await client.refresh(tokenSet);
          // Check again to avoid race conditions.
          if (state.currentTokenSet?.set === tokenSet) {
            this.storeTokenSet(state, refreshedTokens, client);
            return true;
          }
        } catch (err: unknown) {
          this.logger.emit('mongodb-oidc-plugin:refresh-failed', {
            error: errorString(err),
          });
        }
        return false;
      },
    };
  }

  private async authorizationCodeFlow(
    state: UserOIDCAuthState,
    signal: AbortSignal
  ): Promise<void> {
    const { scope, issuerParams, clientParams } =
      this.getInitialOIDCIssuerAndClientParams(state.serverOIDCMetadata);

    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);

    let issuer = new Issuer(issuerParams);
    let client = new issuer.Client(clientParams);

    const server = new RFC8252HTTPServer({
      redirectUrl: this.getRedirectURI(),
      logger: this.logger,
    });
    const oidcStateParam = (await promisify(randomBytes)(16)).toString('hex');
    let paramsUrl = '';

    try {
      await withAbortCheck(signal, async ({ signalCheck, signalPromise }) => {
        await Promise.race([server.listen(), signalPromise]);

        const authCodeFlowUrl = client.authorizationUrl({
          scope,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          state: oidcStateParam,
        });
        const { localUrl, onAccessed: onLocalUrlAccessed } =
          await server.addRedirect(authCodeFlowUrl);

        signalCheck();
        const browserHandle = await this.openBrowser({ url: localUrl, signal });
        const browserStatePromise = new Promise<never>((resolve, reject) => {
          browserHandle?.once('error', (err) => reject(err));
          browserHandle?.once('exit', (code) => {
            if (code !== 0)
              reject(
                new MongoDBOIDCError(
                  `Opening browser failed with exit code ${code}`
                )
              );
          });
        });

        const timeout: Promise<never> = new Promise((resolve, reject) => {
          if (this.options.openBrowserTimeout !== 0) {
            setTimeout(
              reject,
              this.options.openBrowserTimeout ?? kDefaultOpenBrowserTimeout,
              new MongoDBOIDCError('Opening browser timed out')
            ).unref();
          }
        });

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
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (err: any) {
      // Tell the outer logic here to fallback to device auth flow if it is
      // available if any of the steps above failed.
      if (Object.isExtensible(err)) {
        err[kEnableFallback] = true;
      }
      throw err;
    } finally {
      await server.close();
    }

    const params = client.callbackParams(paramsUrl);
    // The oidc-client library requires `issuer` to be set here; we did not
    // set it when we assembled the original `issuerParams` (because it was
    // not available as information), but we should have received it from the
    // callback parameters and can set it here.
    issuerParams.issuer = String(params.iss);
    issuer = new Issuer(issuerParams);
    client = new issuer.Client(clientParams);
    client.validateIdToken = () => {
      // Do not attempt to validate the ID token. The client library would
      // do this by default, but we do not have access to the necessary
      // JWKS here. This is in direct conflict with the OIDC spec (!!)
      // https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation:
      //
      // > Clients MUST validate the ID Token in the Token Response in the following manner: [...]
      //
      // We accept this because for the purposes of this plugin, we do not
      // interact with the identity token, nor do we actually consume the
      // access token. We leave it to the the server to validate that the token is
      // valid, refers to the right identity, and comes from the right source.
    };
    const tokenSet = await client.callback(this.getRedirectURI(), params, {
      code_verifier: codeVerifier,
      state: oidcStateParam,
    });
    this.storeTokenSet(state, tokenSet, client);
  }

  private async deviceAuthorizationFlow(
    state: UserOIDCAuthState,
    signal: AbortSignal
  ): Promise<void> {
    const { scope, issuerParams, clientParams } =
      this.getInitialOIDCIssuerAndClientParams(state.serverOIDCMetadata);

    const issuer = new Issuer(issuerParams);
    const client = new issuer.Client(clientParams);

    client.validateIdToken = () => {
      /* see above */
    };
    await withAbortCheck(signal, async ({ signalCheck, signalPromise }) => {
      const deviceFlowHandle = await Promise.race([
        client.deviceAuthorization({
          client_id: clientParams.client_id,
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
      this.storeTokenSet(state, tokenSet, client);
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
    principalName: string | undefined,
    serverMetadata: OIDCMechanismServerStep1,
    driverAbortSignal?: OIDCAbortSignal | number
  ): Promise<OIDCRequestTokenResult> {
    const state = this.getAuthState(serverMetadata, principalName);

    if (state.currentAuthAttempt) {
      return await state.currentAuthAttempt;
    }

    // The currently plan is for the 6.x driver (which may drop support
    // for Node.js 14.x) to pass in an actual AbortSignal here. For
    // compatibility with the 5.x driver/AbortSignal-less-Node.js, we accept
    // a timeout in milliseconds as well.
    if (typeof driverAbortSignal === 'number') {
      driverAbortSignal = timeoutSignal(driverAbortSignal);
    }

    const newAuthAttempt = this.initiateAuthAttempt(state, driverAbortSignal);
    state.currentAuthAttempt = newAuthAttempt;
    newAuthAttempt.finally(() => {
      if (state.currentAuthAttempt === newAuthAttempt)
        state.currentAuthAttempt = null;
    });
    return newAuthAttempt;
  }

  public async refreshToken(
    principalName: string | undefined,
    serverMetadata: OIDCMechanismServerStep1,
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    previousResult: OIDCRequestTokenResult,
    driverAbortSignal?: OIDCAbortSignal | number
  ): Promise<OIDCRequestTokenResult> {
    return await this.requestToken(
      principalName,
      serverMetadata,
      driverAbortSignal
    );
  }
}
