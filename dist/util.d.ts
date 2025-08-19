import type { IDToken, JsonValue, TokenEndpointResponse, TokenEndpointResponseHelpers } from 'openid-client';
import { MongoDBOIDCError, type OIDCAbortSignal } from './types';
import type { Readable } from 'stream';
export declare function throwIfAborted(signal?: OIDCAbortSignal): void;
interface AbortCheckArgs {
    signalCheck: () => void;
    signalPromise: Promise<never>;
}
export declare function withAbortCheck<T extends (abortCheck: AbortCheckArgs) => Promise<any>>(signal: OIDCAbortSignal | undefined, fn: T): Promise<ReturnType<T>>;
export declare function timeoutSignal(ms: number): AbortSignal;
export declare function withLock<T extends (...args: any[]) => Promise<any>>(fn: T): (...args: Parameters<T>) => ReturnType<T>;
export declare function normalizeObject<T extends object>(obj: T): T;
export declare function validateSecureHTTPUrl(url: string | URL | undefined | null | JsonValue, diagnosticId: string): 'http-allowed' | 'http-disallowed';
export declare function errorString(err: unknown): string;
export declare function getRefreshTokenId(token: string | null | undefined): string | null;
export declare class TokenSet {
    private readonly response;
    readonly expiresAt: number | undefined;
    constructor(response: TokenEndpointResponse & TokenEndpointResponseHelpers, expiresAt?: number | undefined);
    get refreshToken(): string | undefined;
    get accessToken(): string | undefined;
    get idToken(): string | undefined;
    get idTokenClaims(): IDToken | undefined;
    get tokenType(): TokenEndpointResponse['token_type'];
    serialize(): {
        claims: {
            [claim: string]: JsonValue | undefined;
            iss: string;
            sub: string;
            aud: string | string[];
            iat: number;
            exp: number;
            nonce?: string;
            auth_time?: number;
            azp?: string;
            jti?: string;
            nbf?: number;
            cnf?: import("oauth4webapi").ConfirmationClaims;
        } | undefined;
        expiresAt: number | undefined;
        expiresIn: undefined;
        access_token: string;
        expires_in?: number;
        id_token?: string;
        refresh_token?: string;
        scope?: string;
        authorization_details?: import("oauth4webapi").AuthorizationDetails[];
        token_type: "bearer" | "dpop" | Lowercase<string>;
    };
    static fromSerialized(serialized: ReturnType<(typeof TokenSet.prototype)['serialize']>): TokenSet;
    stableId(): string;
}
export declare function improveHTTPResponseBasedError<T>(err: T): Promise<T | MongoDBOIDCError>;
export declare function streamIsNodeReadable(stream: unknown): stream is Readable;
export declare function nodeFetchCompat(response: Response & {
    body: Readable | ReadableStream | null;
}): Response;
export {};
//# sourceMappingURL=util.d.ts.map