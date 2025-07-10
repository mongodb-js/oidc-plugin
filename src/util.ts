import type {
  IDToken,
  JsonValue,
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from 'openid-client';
import { MongoDBOIDCError, type OIDCAbortSignal } from './types';
import { createHash, randomBytes } from 'crypto';

class AbortError extends Error {
  constructor() {
    super('The operation was aborted');
  }
}

export function throwIfAborted(signal?: OIDCAbortSignal): void {
  if (signal?.aborted) throw signal.reason ?? new AbortError();
}

interface AbortCheckArgs {
  signalCheck: () => void;
  signalPromise: Promise<never>;
}
export async function withAbortCheck<
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  T extends (abortCheck: AbortCheckArgs) => Promise<any>
>(signal: OIDCAbortSignal | undefined, fn: T): Promise<ReturnType<T>> {
  const signalCheck = () => throwIfAborted(signal);
  let reject: (err: unknown) => void;
  const signalPromise = new Promise<never>((resolve, rej) => {
    reject = rej;
  });
  function listener() {
    reject(signal?.reason ?? new AbortError());
  }
  signalPromise.catch(() => {
    /* squelch UnhandledPromiseRejectionWarning */
  });

  signalCheck();
  signal?.addEventListener('abort', listener, { once: true });
  try {
    return await fn({ signalCheck, signalPromise });
  } finally {
    signal?.removeEventListener('abort', listener);
  }
}

export function errorString(err: unknown): string {
  return String(
    typeof err === 'object' && err && 'message' in err ? err.message : err
  );
}

// AbortSignal.timeout, but consistently .unref()ed
export function timeoutSignal(ms: number): AbortSignal {
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms).unref();
  return controller.signal;
}

// Ensure that only one call to the target `fn` is active at a time.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function withLock<T extends (...args: any[]) => Promise<any>>(
  fn: T
): (...args: Parameters<T>) => ReturnType<T> {
  // `lock` represents the completion of the current call to fn(), if any.
  let lock: Promise<void> = Promise.resolve();
  return (...args: Parameters<T>) => {
    const result = lock
      .then(() => fn(...args))
      .finally(() => {
        lock = Promise.resolve();
      }) as ReturnType<T>;
    lock = result.catch(() => {
      /* handled by caller */
    });
    return result;
  };
}

// Normalize JS objects by sorting keys so that {a:1,b:2} and {b:2,a:1} are equivalent.
// eslint-disable-next-line @typescript-eslint/ban-types
export function normalizeObject<T extends object>(obj: T): T {
  return Object.fromEntries(Object.entries(obj).sort()) as T;
}

function isURL(url: unknown): url is URL {
  return Object.prototype.toString.call(url).toLowerCase() === '[object url]';
}

// Throws if the url does not refer to an https: endpoint or a local endpoint, or null or undefined.
export function validateSecureHTTPUrl(
  url: string | URL | undefined | null | JsonValue,
  diagnosticId: string
): 'http-allowed' | 'http-disallowed' {
  try {
    // eslint-disable-next-line eqeqeq
    if (url == null) return 'http-disallowed';
    if (typeof url !== 'string' && !isURL(url))
      throw new Error(
        `Expected string or URL object, got ${typeof url} instead`
      );
    const parsed: URL = isURL(url) ? url : new URL(url);
    if (parsed.protocol === 'https:') return 'http-disallowed';
    if (parsed.protocol !== 'http:') {
      throw new Error(`Unknown protocol '${parsed.protocol}' '${String(url)}'`);
    }
    if (!/^(\[::1\]|127(\.\d+){3}|localhost)$/.test(parsed.hostname)) {
      throw new Error(
        `Need to specify https: when accessing non-local URL '${String(url)}'`
      );
    }
    return 'http-allowed';
  } catch (err: unknown) {
    if (
      !err ||
      typeof err !== 'object' ||
      !('message' in err) ||
      typeof err.message !== 'string'
    ) {
      throw err;
    }
    err.message += ` (validating: ${diagnosticId})`;
    throw err;
  }
}

export function messageFromError(err: unknown): string {
  return String(
    err &&
      typeof err === 'object' &&
      'message' in err &&
      typeof err.message === 'string'
      ? err.message
      : err
  );
}

const salt = randomBytes(16);
export function getRefreshTokenId(
  token: string | null | undefined
): string | null {
  if (!token) return null;
  // Add a prefix to indicate that this isn't an actual refresh token,
  // that might unnecessarily worry users
  return (
    'debugid:' + createHash('sha256').update(salt).update(token).digest('hex')
  );
}

export class TokenSet {
  private readonly response: Readonly<TokenEndpointResponse> &
    TokenEndpointResponseHelpers;
  public readonly expiresAt: number | undefined;

  constructor(
    response: TokenEndpointResponse & TokenEndpointResponseHelpers,
    expiresAt?: number | undefined
  ) {
    this.response = response;
    this.expiresAt =
      expiresAt ??
      (() => {
        const expiresIn: number | undefined = this.response.expiresIn();
        return expiresIn
          ? Math.floor(Date.now() / 1000) + expiresIn
          : undefined;
      })();
  }

  get refreshToken(): string | undefined {
    return this.response.refresh_token;
  }

  get accessToken(): string | undefined {
    return this.response.access_token;
  }

  get idToken(): string | undefined {
    return this.response.id_token;
  }

  get idTokenClaims(): IDToken | undefined {
    return this.response.claims();
  }

  get tokenType(): TokenEndpointResponse['token_type'] {
    return this.response.token_type;
  }

  // Explicitly expressing the return type of this function is a bit awkward,
  // and since it is only consumed by `fromSerialized`, it's fine to leave it inferred.
  serialize() {
    const expiresIn: number | undefined = this.response.expiresIn();
    const claims = this.response.claims();
    return {
      ...this.response,
      claims: claims ? { ...claims } : undefined,
      expiresAt:
        this.expiresAt ??
        (expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : undefined),
      expiresIn: undefined,
    };
  }

  static fromSerialized(
    serialized: ReturnType<(typeof TokenSet.prototype)['serialize']>
  ): TokenSet {
    const helpers: TokenEndpointResponseHelpers = {
      claims: () => serialized.claims,
      expiresIn: () =>
        serialized.expiresAt &&
        Math.max(0, serialized.expiresAt - Math.floor(Date.now() / 1000)),
    };
    return new this(
      Object.assign({ ...serialized }, helpers),
      serialized.expiresAt
    );
  }

  // Identify a token set based on a hash of its contents
  stableId(): string {
    const { access_token, id_token, refresh_token, token_type } = this.response;
    return createHash('sha256')
      .update(
        JSON.stringify({
          access_token,
          id_token,
          refresh_token,
          token_type,
          expires_at: this.expiresAt,
        })
      )
      .digest('hex');
  }
}

// openid-client@6.x has reduced error messages for HTTP errors significantly, reducing e.g.
// an HTTP error to just a simple 'unexpect HTTP response status code' message, without
// further diagnostic information. So if the `cause` of an `err` object is a fetch `Response`
// object, we try to throw a more helpful error.
export async function improveHTTPResponseBasedError<T>(
  err: T
): Promise<T | MongoDBOIDCError> {
  if (
    err &&
    typeof err === 'object' &&
    'cause' in err &&
    err.cause &&
    typeof err.cause === 'object' &&
    'status' in err.cause &&
    'statusText' in err.cause &&
    'text' in err.cause &&
    typeof err.cause.text === 'function'
  ) {
    try {
      let body = '';
      try {
        body = await err.cause.text();
      } catch {
        // ignore
      }
      let errorMessageFromBody = '';
      try {
        const parsed = JSON.parse(body);
        errorMessageFromBody =
          ': ' + String(parsed.error_description || parsed.error || '');
      } catch {
        // ignore
      }
      if (!errorMessageFromBody) errorMessageFromBody = `: ${body}`;
      return new MongoDBOIDCError(
        `${errorString(err)}: caused by HTTP response ${String(
          err.cause.status
        )} (${String(err.cause.statusText)})${errorMessageFromBody}`,
        { codeName: 'HTTPResponseError', cause: err }
      );
    } catch {
      return err;
    }
  }
  return err;
}
