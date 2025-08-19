import type { MongoDBOIDCLogEventsMap, OIDCCallbackParams, IdPServerResponse, TypedEventEmitter } from './types';
import { TokenSet } from './util';
import type { MongoDBOIDCPlugin, MongoDBOIDCPluginOptions } from './api';
import { type IDToken } from 'openid-client';
type TokenSetExpiryInfo = Partial<Pick<TokenSet, 'refreshToken' | 'expiresAt'>> & {
    idTokenClaims?: Pick<IDToken, 'exp'> | undefined;
};
/** @internal Exported for testing only */
export declare function automaticRefreshTimeoutMS(tokenSet: TokenSetExpiryInfo, passIdTokenAsAccessToken?: boolean, now?: number): number | undefined;
/** @internal */
export declare class MongoDBOIDCPluginImpl implements MongoDBOIDCPlugin {
    private readonly options;
    readonly logger: TypedEventEmitter<MongoDBOIDCLogEventsMap>;
    private readonly mapIdpToAuthState;
    readonly mongoClientOptions: MongoDBOIDCPlugin['mongoClientOptions'];
    private readonly timers;
    private destroyed;
    constructor(options: Readonly<MongoDBOIDCPluginOptions>);
    /** @internal Public for testing only. */
    static createOIDCAuthStateId(): string;
    private _deserialize;
    private _serialize;
    serialize(): Promise<string>;
    private getAllowedFlows;
    private getAuthState;
    private getSupportedDefaultScopes;
    private fetch;
    private doFetch;
    private getOIDCClientConfiguration;
    private openBrowser;
    private notifyDeviceFlow;
    private updateStateWithTokenSet;
    static readonly defaultRedirectURI = "http://localhost:27097/redirect";
    private authorizationCodeFlow;
    private deviceAuthorizationFlow;
    private initiateAuthAttempt;
    requestToken(params: OIDCCallbackParams): Promise<IdPServerResponse>;
    destroy(): Promise<void>;
}
export {};
//# sourceMappingURL=plugin.d.ts.map