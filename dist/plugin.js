"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.MongoDBOIDCPluginImpl = void 0;
exports.automaticRefreshTimeoutMS = automaticRefreshTimeoutMS;
const types_1 = require("./types");
const util_1 = require("./util");
const rfc_8252_http_server_1 = require("./rfc-8252-http-server");
const events_1 = require("events");
const api_1 = require("./api");
const child_process_1 = require("child_process");
const openid_client_1 = require("openid-client");
const https_1 = require("https");
const http_1 = require("http");
// eslint-disable-next-line @typescript-eslint/consistent-type-imports
let _electron = undefined;
async function getDefaultOpenBrowser() {
    // If running electron, use electron.shell.openExternal() by default
    // to open a browser.
    if (process.versions.electron && _electron !== 'cannot-require') {
        try {
            _electron ??= await Promise.resolve().then(() => __importStar(require('electron')));
            return ({ url }) => 
            // eslint-disable-next-line @typescript-eslint/consistent-type-imports
            _electron.shell.openExternal(url);
        }
        catch {
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
        let open;
        try {
            open = (await Promise.resolve().then(() => __importStar(require('open')))).default;
        }
        catch (err) {
            if (err &&
                typeof err === 'object' &&
                'code' in err &&
                err.code === 'ERR_REQUIRE_ESM' &&
                typeof __webpack_require__ === 'undefined') {
                // This means that the import() above was transpiled to require()
                // and that that require() called failed because it saw actual on-disk ESM.
                // In this case, it should be safe to use eval'ed import().
                open = (await eval("import('open')")).default;
            }
            else {
                throw err;
            }
        }
        const child = await open(url);
        child.unref();
        return child;
    };
}
function tokenExpiryInSeconds(tokenSet = {}, passIdTokenAsAccessToken = false, now = Date.now()) {
    // If we have an ID token and are supposed to use it, its `exp` claim
    // specifies the token expiry. Otherwise, we assume that the `expires_at`
    // value presented by the OIDC provider is correct, since OIDC clients are
    // not supposed to inspect access tokens and treat them as opaque.
    const expiresAt = (tokenSet.idTokenClaims?.exp !== undefined &&
        passIdTokenAsAccessToken &&
        tokenSet.idTokenClaims?.exp) ||
        tokenSet.expiresAt ||
        0;
    return Math.max(0, (expiresAt ?? 0) - now / 1000);
}
/** @internal Exported for testing only */
function automaticRefreshTimeoutMS(tokenSet, passIdTokenAsAccessToken = false, now = Date.now()) {
    const expiresIn = tokenExpiryInSeconds(tokenSet, passIdTokenAsAccessToken, now);
    if (!tokenSet.refreshToken || !expiresIn)
        return;
    // If the tokens expire in more than 1 minute, automatically register
    // a refresh handler. (They should not expire in less; however,
    // if we didn't handle that case, we'd run the risk of refreshing very
    // frequently.) Refresh the token 5 minutes before expiration or
    // halfway between now and the expiration time, whichever comes later
    // (expires in 1 hour -> refresh in 55 min, expires in 5 min -> refresh in 2.5 min).
    if (expiresIn >= 60 /* 1 minute */) {
        return Math.max(expiresIn - 300 /* 5 minutes */, expiresIn / 2) * 1000;
    }
}
const kEnableFallback = Symbol.for('@@mdb.oidcplugin.kEnableFallback');
let updateIdCounter = 0;
let authStateIdCounter = 0;
function allowFallbackIfFailed(promise) {
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
class MongoDBOIDCPluginImpl {
    options;
    logger;
    mapIdpToAuthState = new Map();
    mongoClientOptions;
    timers;
    destroyed = false;
    constructor(options) {
        this.options = options;
        this.logger = options.logger ?? new events_1.EventEmitter();
        this.mongoClientOptions = {
            authMechanismProperties: {
                OIDC_HUMAN_CALLBACK: this.requestToken.bind(this),
            },
        };
        this.timers = { setTimeout, clearTimeout };
        if (options.serializedState) {
            this._deserialize(options.serializedState);
        }
    }
    /** @internal Public for testing only. */
    static createOIDCAuthStateId() {
        // Use an ID for the OIDC auth state, so that we can distinguish
        // between different auth states in logs.
        return `${Date.now().toString(32)}-${authStateIdCounter++}`;
    }
    _deserialize(serialized) {
        try {
            let original;
            try {
                original = JSON.parse(Buffer.from(serialized, 'base64').toString('utf8'));
            }
            catch (err) {
                throw new types_1.MongoDBOIDCError(`Stored OIDC data could not be deserialized: ${err.message}`, { cause: err, codeName: 'DeserializeFormatMismatch' });
            }
            if (original.oidcPluginStateVersion !== 1) {
                throw new types_1.MongoDBOIDCError(`Stored OIDC data could not be deserialized because of a version mismatch (got ${JSON.stringify(original.oidcPluginStateVersion)}, expected 1)`, { codeName: 'DeserializeVersionMismatch' });
            }
            for (const [key, serializedState] of original.state) {
                const state = {
                    id: serializedState.id ?? MongoDBOIDCPluginImpl.createOIDCAuthStateId(),
                    serverOIDCMetadata: { ...serializedState.serverOIDCMetadata },
                    currentAuthAttempt: null,
                    currentTokenSet: null,
                    lastIdTokenClaims: serializedState.lastIdTokenClaims
                        ? { ...serializedState.lastIdTokenClaims }
                        : undefined,
                    discardingTokenSets: serializedState.discardingTokenSets,
                };
                if (serializedState.currentTokenSet.set) {
                    this.updateStateWithTokenSet(state, util_1.TokenSet.fromSerialized(serializedState.currentTokenSet.set));
                }
                this.mapIdpToAuthState.set(key, state);
            }
        }
        catch (err) {
            this.logger.emit('mongodb-oidc-plugin:deserialization-failed', {
                error: err.message,
            });
            // It's not necessary to throw by default here since failure to
            // deserialize previous state means that, at worst, users will have
            // to re-authenticate.
            if (this.options.throwOnIncompatibleSerializedState)
                throw err;
        }
    }
    // Separate method so we can re-use the inferred return type in _deserialize()
    _serialize() {
        return {
            oidcPluginStateVersion: 1,
            state: [...this.mapIdpToAuthState]
                .filter(([, state]) => !!state.currentTokenSet)
                .map(([key, state]) => {
                return [
                    key,
                    {
                        id: state.id,
                        serverOIDCMetadata: { ...state.serverOIDCMetadata },
                        currentTokenSet: {
                            set: state.currentTokenSet?.set?.serialize(),
                        },
                        lastIdTokenClaims: state.lastIdTokenClaims
                            ? { ...state.lastIdTokenClaims }
                            : undefined,
                        discardingTokenSets: state.discardingTokenSets ?? [],
                    },
                ];
            }),
        };
    }
    serialize() {
        // Wrap the result using JS-to-JSON-to-UTF8-to-Base64. We could probably
        // omit the base64 encoding, but this makes it clearer that it's an opaque
        // value that's not intended to be inspected or modified.
        return Promise.resolve(Buffer.from(JSON.stringify(this._serialize()), 'utf8').toString('base64'));
    }
    // Is this flow supported and allowed?
    async getAllowedFlows({ signal, }) {
        const flowList = new Set(typeof this.options.allowedFlows === 'function'
            ? await this.options.allowedFlows({ signal })
            : this.options.allowedFlows ?? ['auth-code']);
        // Remove flows from the set whose prerequisites aren't fulfilled.
        if (this.options.openBrowser === false)
            flowList.delete('auth-code');
        if (!this.options.notifyDeviceFlow)
            flowList.delete('device-auth');
        return [...flowList];
    }
    // Return the current state for a given [server, username] configuration,
    // or create a new one if none exists.
    getAuthState(serverMetadata) {
        if (!serverMetadata.issuer || typeof serverMetadata.issuer !== 'string') {
            throw new types_1.MongoDBOIDCError(`'issuer' is missing`, {
                codeName: 'MissingIssuer',
            });
        }
        (0, util_1.validateSecureHTTPUrl)(serverMetadata.issuer, 'issuer');
        if (!serverMetadata.clientId) {
            throw new types_1.MongoDBOIDCError('No clientId passed in server OIDC metadata object', { codeName: 'MissingClientId' });
        }
        const key = JSON.stringify({
            // If any part of the server metadata changes, we should probably use
            // a new cache entry.
            ...(0, util_1.normalizeObject)(serverMetadata),
        });
        const existing = this.mapIdpToAuthState.get(key);
        if (existing)
            return existing;
        const newState = {
            serverOIDCMetadata: serverMetadata,
            id: MongoDBOIDCPluginImpl.createOIDCAuthStateId(),
            currentAuthAttempt: null,
            currentTokenSet: null,
        };
        this.mapIdpToAuthState.set(key, newState);
        return newState;
    }
    getSupportedDefaultScopes(idpMetadata) {
        return ['openid', 'offline_access'].filter((scope) => {
            // Only add `openid` / `offline_access` if the IdP announces support
            // for those scopes, or if the IdP does not provide a list of scopes
            // and we cannot tell which it supports.
            // https://jira.mongodb.org/browser/COMPASS-7437
            return (!Array.isArray(idpMetadata.scopes_supported) ||
                idpMetadata.scopes_supported.includes(scope));
        });
    }
    fetch = async (url, init) => {
        this.logger.emit('mongodb-oidc-plugin:outbound-http-request', { url });
        try {
            const response = (0, util_1.nodeFetchCompat)(await this.doFetch(url, init));
            this.logger.emit('mongodb-oidc-plugin:outbound-http-request-completed', {
                url,
                status: response.status,
                statusText: response.statusText,
            });
            return response;
        }
        catch (err) {
            this.logger.emit('mongodb-oidc-plugin:outbound-http-request-failed', {
                url,
                error: (0, util_1.errorString)(err),
            });
            throw err;
        }
    };
    doFetch = async (url, init) => {
        if (this.options.customFetch) {
            return await this.options.customFetch(url, init);
        }
        const options = typeof this.options.customHttpOptions === 'function'
            ? this.options.customHttpOptions(url, {})
            : this.options.customHttpOptions;
        // Same comments as in getDefaultOpenBrowser() apply regarding the import/eval fallbacks here.
        // eslint-disable-next-line @typescript-eslint/consistent-type-imports
        let fetch;
        try {
            fetch = (await Promise.resolve().then(() => __importStar(require('node-fetch')))).default;
        }
        catch (err) {
            if (err &&
                typeof err === 'object' &&
                'code' in err &&
                err.code === 'ERR_REQUIRE_ESM' &&
                typeof __webpack_require__ === 'undefined') {
                fetch = (await eval('import("node-fetch")')).default;
            }
            else {
                throw err;
            }
        }
        const AgentClass = new URL(url).protocol === 'https:' ? https_1.Agent : http_1.Agent;
        return (await fetch(url, {
            ...init,
            agent: options?.agent ?? new AgentClass(options),
            ...options,
            headers: { ...options?.headers },
            // TS is not convinced that node-fetch and built-in fetch are compatible enough
        }));
    };
    async getOIDCClientConfiguration(state, redirectURI) {
        const serverMetadata = state.serverOIDCMetadata;
        const makeScope = (idpMetadata) => [
            ...new Set([
                ...this.getSupportedDefaultScopes(idpMetadata),
                ...(serverMetadata.requestScopes ?? []),
            ]),
        ].join(' ');
        if (state.config) {
            const config = new openid_client_1.Configuration(state.config.serverMetadata(), state.config.clientMetadata().client_id, {
                ...state.config.clientMetadata(),
                redirect_uri: redirectURI,
            });
            config[openid_client_1.customFetch] = this.fetch;
            if ((0, util_1.validateSecureHTTPUrl)(config.serverMetadata().issuer, 'issuer') ===
                'http-allowed') {
                (0, openid_client_1.allowInsecureRequests)(config);
            }
            return {
                scope: makeScope(config.serverMetadata()),
                config,
            };
        }
        const httpAllowed = (0, util_1.validateSecureHTTPUrl)(serverMetadata.issuer, 'issuer');
        const discoveryOptions = {
            [openid_client_1.customFetch]: this.fetch,
            execute: httpAllowed === 'http-allowed' ? [openid_client_1.allowInsecureRequests] : [],
        };
        let config;
        try {
            config = await (0, openid_client_1.discovery)(new URL(serverMetadata.issuer), serverMetadata.clientId, {
                redirect_uri: redirectURI,
            }, (0, openid_client_1.None)(), discoveryOptions);
            // NB: The fact that `customFetch` is transfered from `discoveryOptions` to `config`
            // is tested by our unit tests when they verify that all outgoing HTTP calls are logged.
        }
        catch (err) {
            // openid-client just forwards the raw Node.js HTTP error, we'll want to
            // at least include the target URL here
            throw new types_1.MongoDBOIDCError(`Unable to fetch issuer metadata for ${JSON.stringify(serverMetadata.issuer)}: ${(0, util_1.errorString)(err)}`, {
                cause: err,
                codeName: 'IssuerMetadataDiscoveryFailed',
            });
        }
        (0, util_1.validateSecureHTTPUrl)(config.serverMetadata().authorization_endpoint, 'authorization_endpoint');
        (0, util_1.validateSecureHTTPUrl)(config.serverMetadata().device_authorization_endpoint, 'device_authorization_endpoint');
        (0, util_1.validateSecureHTTPUrl)(config.serverMetadata().token_endpoint, 'token_endpoint');
        (0, util_1.validateSecureHTTPUrl)(config.serverMetadata().jwks_uri, 'jwks_uri');
        // Should already have been set by the discovery call, but doesn't hurt to make sure
        config[openid_client_1.customFetch] = this.fetch;
        state.config = config;
        return {
            scope: makeScope(config.serverMetadata()),
            config,
        };
    }
    async openBrowser(options) {
        // Consistency check: options.url is a valid URL and does not contain
        // characters that would have special semantics when passed to a
        // child process spawned with `shell: true`.
        // That might not be true for the URL we got from the IdP, but since we
        // wrap it in our own redirect first anyway, we can guarantee that the
        // URL has this format.
        new URL(options.url);
        if (!/^[a-zA-Z0-9%/:;_.,=@-]+$/.test(options.url)) {
            throw new types_1.MongoDBOIDCError(`Unexpected format for internally generated URL: '${options.url}'`, { codeName: 'GeneratedUrlInvalidForOpenBrowserCommand' });
        }
        this.logger.emit('mongodb-oidc-plugin:open-browser', {
            customOpener: !!this.options.openBrowser,
        });
        if (this.options.openBrowser === false) {
            // We should never really get to this point
            throw new types_1.MongoDBOIDCError('Cannot open browser if `openBrowser` is false', { codeName: 'OpenBrowserDisabled' });
        }
        if (typeof this.options.openBrowser === 'function') {
            return await this.options.openBrowser(options);
        }
        if (this.options.openBrowser === undefined) {
            const defaultOpener = await getDefaultOpenBrowser();
            return await defaultOpener(options);
        }
        if (typeof this.options.openBrowser?.command === 'string') {
            const child = (0, child_process_1.spawn)(this.options.openBrowser.command, [options.url], {
                shell: true,
                stdio: 'ignore',
                detached: true,
                signal: this.options.openBrowser.abortable ? options.signal : undefined,
            });
            child.unref();
            return child;
        }
        throw new types_1.MongoDBOIDCError('Unknown format for `openBrowser`', {
            codeName: 'OpenBrowserOptionFormatUnknown',
        });
    }
    async notifyDeviceFlow(deviceFlowInformation) {
        (0, util_1.validateSecureHTTPUrl)(deviceFlowInformation.verificationUrl, 'verificationUrl');
        if (!this.options.notifyDeviceFlow) {
            // Should never happen.
            throw new types_1.MongoDBOIDCError('notifyDeviceFlow() requested but not provided', { codeName: 'DeviceFlowNotEnabled' });
        }
        this.logger.emit('mongodb-oidc-plugin:notify-device-flow');
        await this.options.notifyDeviceFlow(deviceFlowInformation);
    }
    updateStateWithTokenSet(state, tokenSet) {
        // We intend to be able to pass plugin instances to multiple MongoClient
        // instances that are connecting to the same MongoDB endpoint.
        // We need to prevent a scenario in which a requestToken callback is called
        // for client A, the token expires before it is requested again by client A,
        // then the plugin is passed to client B which requests a token, and we
        // receive mismatching tokens for different users or different audiences.
        if (!tokenSet.idToken &&
            state.lastIdTokenClaims &&
            !state.lastIdTokenClaims.noIdToken) {
            throw new types_1.MongoDBOIDCError(`ID token expected, but not found. Expected claims: ${JSON.stringify(state.lastIdTokenClaims)}`, { codeName: 'IDTokenClaimsMismatchTokenMissing' });
        }
        if (tokenSet.idToken &&
            state.lastIdTokenClaims &&
            state.lastIdTokenClaims.noIdToken) {
            throw new types_1.MongoDBOIDCError(`Unexpected ID token received.`, {
                codeName: 'IDTokenClaimsMismatchTokenUnexpectedlyPresent',
            });
        }
        if (tokenSet.idToken) {
            const idTokenClaims = tokenSet.idTokenClaims;
            if (!idTokenClaims)
                throw new types_1.MongoDBOIDCError('Internal error: id_token set but claims() unavailable', { codeName: 'IDTokenClaimsUnavailable' });
            if (state.lastIdTokenClaims && !state.lastIdTokenClaims.noIdToken) {
                for (const claim of ['aud', 'sub']) {
                    const normalize = (value) => {
                        return JSON.stringify(Array.isArray(value) ? [...value].sort() : value);
                    };
                    const knownClaim = normalize(state.lastIdTokenClaims[claim]);
                    const newClaim = normalize(idTokenClaims[claim]);
                    if (knownClaim !== newClaim) {
                        throw new types_1.MongoDBOIDCError(`Unexpected '${claim}' field in id token: Expected ${knownClaim}, saw ${newClaim}`, { codeName: 'IDTokenClaimsMismatchClaimMismatch' });
                    }
                }
            }
            state.lastIdTokenClaims = {
                aud: idTokenClaims.aud,
                sub: idTokenClaims.sub,
            };
        }
        else {
            state.lastIdTokenClaims = { noIdToken: true };
            this.logger.emit('mongodb-oidc-plugin:missing-id-token');
        }
        const refreshTokenId = (0, util_1.getRefreshTokenId)(tokenSet.refreshToken);
        const updateId = updateIdCounter++;
        const timerDuration = automaticRefreshTimeoutMS(tokenSet, this.options.passIdTokenAsAccessToken);
        // Use `.call()` because in browsers, `setTimeout()` requires that it is called
        // without a `this` value. `.unref()` is not available in browsers either.
        if (state.timer)
            this.timers.clearTimeout.call(null, state.timer);
        state.timer = timerDuration
            ? this.timers.setTimeout.call(null, () => void tryRefresh(), timerDuration)
            : undefined;
        state.timer?.unref?.();
        const tryRefresh = (0, util_1.withLock)(async () => {
            if (state.timer) {
                this.timers.clearTimeout.call(null, state.timer);
                state.timer = undefined;
            }
            // Only refresh this token set if it is the one currently
            // being used.
            if (state.currentTokenSet?.set !== tokenSet) {
                this.logger.emit('mongodb-oidc-plugin:refresh-skipped', {
                    triggeringUpdateId: updateId,
                    expectedRefreshToken: refreshTokenId,
                    actualRefreshToken: (0, util_1.getRefreshTokenId)(state.currentTokenSet?.set?.refreshToken),
                });
                return false;
            }
            try {
                this.logger.emit('mongodb-oidc-plugin:refresh-started', {
                    triggeringUpdateId: updateId,
                    refreshToken: refreshTokenId,
                });
                if (!tokenSet.refreshToken)
                    return false;
                const { config } = await this.getOIDCClientConfiguration(state);
                const refreshedTokens = await (0, openid_client_1.refreshTokenGrant)(config, tokenSet.refreshToken);
                // Check again to avoid race conditions.
                if (state.currentTokenSet?.set === tokenSet) {
                    this.logger.emit('mongodb-oidc-plugin:refresh-succeeded', {
                        triggeringUpdateId: updateId,
                        refreshToken: refreshTokenId,
                    });
                    this.updateStateWithTokenSet(state, new util_1.TokenSet(refreshedTokens));
                    return true;
                }
            }
            catch (err) {
                this.logger.emit('mongodb-oidc-plugin:refresh-failed', {
                    error: (0, util_1.errorString)(err),
                    triggeringUpdateId: updateId,
                    refreshToken: refreshTokenId,
                });
            }
            return false;
        });
        state.currentTokenSet = {
            set: tokenSet,
            tryRefresh,
        };
        this.logger.emit('mongodb-oidc-plugin:state-updated', {
            updateId,
            timerDuration,
            tokenSetId: tokenSet.stableId(),
        });
    }
    static defaultRedirectURI = 'http://localhost:27097/redirect';
    async authorizationCodeFlow(state, signal) {
        const configuredRedirectURI = this.options.redirectURI ?? MongoDBOIDCPluginImpl.defaultRedirectURI;
        const codeVerifier = (0, openid_client_1.randomPKCECodeVerifier)();
        const codeChallenge = await (0, openid_client_1.calculatePKCECodeChallenge)(codeVerifier);
        const oidcStateParam = (0, openid_client_1.randomState)();
        const server = new rfc_8252_http_server_1.RFC8252HTTPServer({
            redirectUrl: configuredRedirectURI,
            logger: this.logger,
            redirectServerRequestHandler: this.options.redirectServerRequestHandler,
            oidcStateParam,
        });
        let paramsUrl = '';
        let scope;
        let config;
        let actualRedirectURI;
        const nonce = this.options.skipNonceInAuthCodeRequest
            ? undefined
            : (0, openid_client_1.randomNonce)();
        try {
            await (0, util_1.withAbortCheck)(signal, async ({ signalCheck, signalPromise }) => {
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
                actualRedirectURI = server.listeningRedirectUrl;
                ({ scope, config } = await this.getOIDCClientConfiguration(state, actualRedirectURI));
                const authCodeFlowUrl = (0, openid_client_1.buildAuthorizationUrl)(config, {
                    scope,
                    code_challenge: codeChallenge,
                    code_challenge_method: 'S256',
                    state: oidcStateParam,
                    ...(nonce ? { nonce } : {}),
                    redirect_uri: actualRedirectURI,
                });
                (0, util_1.validateSecureHTTPUrl)(authCodeFlowUrl, 'authCodeFlowUrl');
                const { localUrl, onAccessed: onLocalUrlAccessed } = await server.addRedirect(authCodeFlowUrl.toString());
                signalCheck();
                // Handle errors from opening a browser but do not await the Promise
                // in case it only resolves when the browser exits (which is the case
                // for the default `open` handler).
                const browserStatePromise = allowFallbackIfFailed(new Promise((resolve, reject) => {
                    this.openBrowser({ url: localUrl, signal })
                        .then((browserHandle) => {
                        this.logger.emit('mongodb-oidc-plugin:open-browser-complete');
                        const extraErrorInfo = () => browserHandle?.spawnargs
                            ? ` (${JSON.stringify(browserHandle.spawnargs)})`
                            : '';
                        browserHandle?.once('error', (err) => reject(new types_1.MongoDBOIDCError(`Opening browser failed with '${(0, util_1.errorString)(err)}'${extraErrorInfo()}`, { cause: err, codeName: 'BrowserOpenFailedSpawnError' })));
                        browserHandle?.once('exit', (code) => {
                            if (code !== 0)
                                reject(new types_1.MongoDBOIDCError(`Opening browser failed with exit code ${code}${extraErrorInfo()}`, { codeName: 'BrowserOpenFailedNonZeroExit' }));
                        });
                    })
                        .catch(reject);
                }));
                const timeout = allowFallbackIfFailed(new Promise((resolve, reject) => {
                    if (this.options.openBrowserTimeout !== 0) {
                        this.timers.setTimeout
                            .call(null, () => reject(new types_1.MongoDBOIDCError('Opening browser timed out', {
                            codeName: 'BrowserOpenTimeout',
                        })), this.options.openBrowserTimeout ?? api_1.kDefaultOpenBrowserTimeout)
                            ?.unref?.();
                    }
                }));
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
        }
        finally {
            await server.close();
        }
        const tokenSet = await (0, openid_client_1.authorizationCodeGrant)(config, new URL(paramsUrl), {
            pkceCodeVerifier: codeVerifier,
            expectedState: oidcStateParam,
            expectedNonce: nonce,
        });
        this.updateStateWithTokenSet(state, new util_1.TokenSet(tokenSet));
    }
    async deviceAuthorizationFlow(state, signal) {
        const { scope, config } = await this.getOIDCClientConfiguration(state);
        await (0, util_1.withAbortCheck)(signal, async ({ signalCheck, signalPromise }) => {
            const deviceFlowHandle = await Promise.race([
                (0, openid_client_1.initiateDeviceAuthorization)(config, {
                    scope,
                }),
                signalPromise,
            ]);
            signalCheck();
            await this.notifyDeviceFlow({
                userCode: deviceFlowHandle.user_code,
                verificationUrl: deviceFlowHandle.verification_uri,
            });
            const tokenSet = await (0, openid_client_1.pollDeviceAuthorizationGrant)(config, deviceFlowHandle, {}, { signal });
            this.updateStateWithTokenSet(state, new util_1.TokenSet(tokenSet));
        });
    }
    async initiateAuthAttempt(state, driverAbortSignal, { forceRefreshOrReauth = false } = {}) {
        (0, util_1.throwIfAborted)(this.options.signal);
        (0, util_1.throwIfAborted)(driverAbortSignal);
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
        const { passIdTokenAsAccessToken } = this.options;
        const signal = combinedAbortController.signal;
        try {
            get_tokens: {
                const currentSetExpiresInSeconds = tokenExpiryInSeconds(state.currentTokenSet?.set, passIdTokenAsAccessToken);
                // If the current token set has a decent amount of validity, just keep using it.
                if (!forceRefreshOrReauth && currentSetExpiresInSeconds > 5 * 60) {
                    this.logger.emit('mongodb-oidc-plugin:skip-auth-attempt', {
                        authStateId: state.id,
                        reason: 'not-expired',
                    });
                    break get_tokens;
                }
                // If the current token set is close to expiry, try to acquire a fresh token
                // if possible.
                if (await state.currentTokenSet?.tryRefresh?.()) {
                    this.logger.emit('mongodb-oidc-plugin:skip-auth-attempt', {
                        authStateId: state.id,
                        reason: 'refresh-succeeded',
                    });
                    break get_tokens;
                }
                // If the current token set is close to expiry, and refreshing failed, that can
                // just mean that the token refresh mechanism are not available.
                // We want to avoid a situation in which two initiateAuthAttempt() calls are made
                // right after each other, the token returned from the first one has a short validity
                // (i.e. up to or less than 5 minutes), and the second one then ignores the token
                // from the first one, effectively keeping the user in a loop of 'overly' eager
                // re-authentication interactions.
                // This means we effectively have a minimum requirement of tokens being valid
                // for at least 10 seconds after being issued OR a working token refresh flow, which
                // seems like a reasonable expectation.
                if (!forceRefreshOrReauth && currentSetExpiresInSeconds > 10) {
                    this.logger.emit('mongodb-oidc-plugin:skip-auth-attempt', {
                        authStateId: state.id,
                        reason: 'not-expired-refresh-failed',
                    });
                    break get_tokens;
                }
                // If no automatic mechanism for acquiring a token is available, we need to start
                // an authentication flow that (typically) involves user interaction.
                state.currentTokenSet = null;
                let error;
                const currentAllowedFlowSet = await this.getAllowedFlows({ signal });
                if (currentAllowedFlowSet.includes('auth-code')) {
                    try {
                        this.logger.emit('mongodb-oidc-plugin:auth-attempt-started', {
                            authStateId: state.id,
                            flow: 'auth-code',
                        });
                        await this.authorizationCodeFlow(state, signal);
                        this.logger.emit('mongodb-oidc-plugin:auth-attempt-succeeded', {
                            authStateId: state.id,
                        });
                        break get_tokens;
                    }
                    catch (err) {
                        error = err;
                        this.logger.emit('mongodb-oidc-plugin:auth-attempt-failed', {
                            authStateId: state.id,
                            error: (0, util_1.errorString)(err),
                        });
                        // eslint-disable-next-line @typescript-eslint/no-explicit-any
                        if (!err?.[kEnableFallback])
                            throw err;
                    }
                }
                if (currentAllowedFlowSet.includes('device-auth')) {
                    try {
                        this.logger.emit('mongodb-oidc-plugin:auth-attempt-started', {
                            authStateId: state.id,
                            flow: 'device-auth',
                        });
                        await this.deviceAuthorizationFlow(state, signal);
                        this.logger.emit('mongodb-oidc-plugin:auth-attempt-succeeded', {
                            authStateId: state.id,
                        });
                        break get_tokens;
                    }
                    catch (err) {
                        this.logger.emit('mongodb-oidc-plugin:auth-attempt-failed', {
                            authStateId: state.id,
                            error: (0, util_1.errorString)(err),
                        });
                        throw err;
                    }
                }
                if (error)
                    throw error;
            }
            if (passIdTokenAsAccessToken && !state.currentTokenSet?.set?.idToken) {
                throw new types_1.MongoDBOIDCError('Could not retrieve valid ID token', {
                    codeName: 'IDTokenMissingFromTokenSet',
                });
            }
            else if (!state.currentTokenSet?.set?.accessToken) {
                throw new types_1.MongoDBOIDCError('Could not retrieve valid access token', {
                    codeName: 'AccessTokenMissingFromTokenSet',
                });
            }
        }
        catch (err) {
            this.logger.emit('mongodb-oidc-plugin:auth-failed', {
                authStateId: state.id,
                error: (0, util_1.errorString)(err),
            });
            throw await (0, util_1.improveHTTPResponseBasedError)(err);
        }
        finally {
            this.options.signal?.removeEventListener('abort', optionsAbortCb);
            driverAbortSignal?.removeEventListener('abort', driverAbortCb);
        }
        const { tokenType, accessToken, idToken, refreshToken } = state.currentTokenSet.set;
        const expiresAt = state.currentTokenSet.set.expiresAt;
        const tokenSetId = state.currentTokenSet.set.stableId();
        // We would not want to return the access token or ID token of a token set whose
        // accompanying refresh token was passed to us by the driver
        const willRetryWithForceRefreshOrReauth = !forceRefreshOrReauth &&
            !!state.discardingTokenSets?.includes(tokenSetId);
        this.logger.emit('mongodb-oidc-plugin:auth-succeeded', {
            authStateId: state.id,
            tokenType: tokenType ?? null, // DPoP or Bearer
            refreshToken: (0, util_1.getRefreshTokenId)(refreshToken),
            expiresAt: expiresAt ? new Date(expiresAt * 1000).toISOString() : null,
            passIdTokenAsAccessToken: !!passIdTokenAsAccessToken,
            tokens: {
                accessToken: accessToken,
                idToken: idToken,
                refreshToken: refreshToken,
            },
            tokenSetId,
            forceRefreshOrReauth,
            willRetryWithForceRefreshOrReauth,
        });
        if (willRetryWithForceRefreshOrReauth) {
            return await this.initiateAuthAttempt(state, driverAbortSignal, {
                forceRefreshOrReauth: true,
            });
        }
        return {
            accessToken: passIdTokenAsAccessToken ? idToken || '' : accessToken,
            refreshToken: tokenSetId,
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
    async requestToken(params) {
        this.logger.emit('mongodb-oidc-plugin:received-server-params', { params });
        if (params.version !== 1) {
            throw new types_1.MongoDBOIDCError(
            // eslint-disable-next-line @typescript-eslint/restrict-template-expressions
            `OIDC MongoDB driver protocol mismatch: unknown version ${params.version}`, { codeName: 'ProtocolVersionMismatch' });
        }
        if (this.destroyed) {
            throw new types_1.MongoDBOIDCError('This OIDC plugin instance has been destroyed and is no longer active', { codeName: 'PluginInstanceDestroyed' });
        }
        if (!params.idpInfo) {
            throw new types_1.MongoDBOIDCError('No IdP information provided', {
                codeName: 'IdPInfoMissing',
            });
        }
        const state = this.getAuthState({
            ...params.idpInfo,
            username: params.username,
        });
        this.logger.emit('mongodb-oidc-plugin:request-token-started', {
            authStateId: state.id,
            isCurrentAuthAttemptSet: !!state.currentAuthAttempt,
            tokenSetId: params.refreshToken,
            username: state.serverOIDCMetadata.username,
            issuer: state.serverOIDCMetadata.issuer,
            clientId: state.serverOIDCMetadata.clientId,
            requestScopes: state.serverOIDCMetadata.requestScopes,
        });
        // If the driver called us with a refresh token, that means that its corresponding
        // access token has become invalid and we should always return a new one.
        if (params.refreshToken) {
            (state.discardingTokenSets ??= []).push(params.refreshToken);
            this.logger.emit('mongodb-oidc-plugin:discarding-token-set', {
                tokenSetId: params.refreshToken,
            });
        }
        try {
            if (state.currentAuthAttempt) {
                return await state.currentAuthAttempt;
            }
            const newAuthAttempt = this.initiateAuthAttempt(state, params.timeoutContext);
            try {
                state.currentAuthAttempt = newAuthAttempt;
                return await newAuthAttempt;
            }
            finally {
                if (state.currentAuthAttempt === newAuthAttempt)
                    state.currentAuthAttempt = null;
            }
        }
        finally {
            this.logger.emit('mongodb-oidc-plugin:request-token-ended', {
                authStateId: state.id,
                isCurrentAuthAttemptSet: !!state.currentAuthAttempt,
                tokenSetId: params.refreshToken,
                username: state.serverOIDCMetadata.username,
                issuer: state.serverOIDCMetadata.issuer,
                clientId: state.serverOIDCMetadata.clientId,
                requestScopes: state.serverOIDCMetadata.requestScopes,
            });
            if (params.refreshToken) {
                const index = state.discardingTokenSets?.indexOf(params.refreshToken) ?? -1;
                if (index > 0) {
                    state.discardingTokenSets?.splice(index, 1);
                }
            }
        }
    }
    // eslint-disable-next-line @typescript-eslint/require-await
    async destroy() {
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
exports.MongoDBOIDCPluginImpl = MongoDBOIDCPluginImpl;
//# sourceMappingURL=plugin.js.map