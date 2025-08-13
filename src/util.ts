import type {
  IDToken,
  JsonValue,
  TokenEndpointResponse,
  TokenEndpointResponseHelpers,
} from 'openid-client';
import { MongoDBOIDCError, type OIDCAbortSignal } from './types';
import { createHash, randomBytes } from 'crypto';
import type { Readable } from 'stream';

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

export function errorString(err: unknown): string {
  if (
    !err ||
    typeof err !== 'object' ||
    !('message' in err) ||
    typeof err.message !== 'string'
  ) {
    const asString = String(err);
    if (asString.toLowerCase() === '[object object]')
      return JSON.stringify(err);

    return asString;
  }
  const cause = getCause(err);
  let { message } = err;
  if (cause) {
    const causeMessage = errorString(cause);
    if (!message.includes(causeMessage))
      message += ` (caused by: ${causeMessage})`;
  }
  return message;
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

function getCause(err: unknown): Record<string, unknown> | undefined {
  if (
    err &&
    typeof err === 'object' &&
    'cause' in err &&
    err.cause &&
    typeof err.cause === 'object'
  ) {
    return err.cause as Record<string, unknown>;
  }
}

// openid-client@6.x has reduced error messages for HTTP errors significantly, reducing e.g.
// an HTTP error to just a simple 'unexpect HTTP response status code' message, without
// further diagnostic information. So if the `cause` of an `err` object is a fetch `Response`
// object, we try to throw a more helpful error.
export async function improveHTTPResponseBasedError<T>(
  err: T
): Promise<T | MongoDBOIDCError> {
  // Note: `err.cause` can either be an `Error` object itself, or a `Response`, or a JSON HTTP response body
  const cause = getCause(err);
  if (cause) {
    try {
      const statusObject =
        'status' in cause ? cause : (err as Record<string, unknown>);
      if (!statusObject.status) return err;

      let body = '';
      try {
        if ('text' in cause && typeof cause.text === 'function')
          body = await cause.text(); // Handle the `Response` case
      } catch {
        // ignore
      }
      let errorMessageFromBody = '';
      try {
        let parsed: Record<string, unknown> = cause;
        try {
          parsed = JSON.parse(body);
        } catch {
          // ignore, and maybe `parsed` already contains the parsed JSON body anyway
        }
        errorMessageFromBody =
          ': ' +
          [parsed.error, parsed.error_description]
            .filter(Boolean)
            .map(String)
            .join(', ');
      } catch {
        // ignore
      }
      if (!errorMessageFromBody) errorMessageFromBody = `: ${body}`;

      const statusTextInsert =
        'statusText' in statusObject
          ? `(${String(statusObject.statusText)})`
          : '';
      return new MongoDBOIDCError(
        `${errorString(err)}: caused by HTTP response ${String(
          statusObject.status
        )} ${statusTextInsert}${errorMessageFromBody}`,
        { codeName: 'HTTPResponseError', cause: err }
      );
    } catch {
      return err;
    }
  }
  return err;
}

// Check whether converting a Node.js `Readable` stream to a web `ReadableStream`
// is possible. We use this for compatibility with fetch() implementations that
// return Node.js `Readable` streams like node-fetch.
export function streamIsNodeReadable(stream: unknown): stream is Readable {
  return !!(
    stream &&
    typeof stream === 'object' &&
    'pipe' in stream &&
    typeof stream.pipe === 'function' &&
    (!('cancel' in stream) || !stream.cancel)
  );
}

export function nodeFetchCompat(
  response: Response & { body: Readable | ReadableStream | null }
): Response {
  const notImplemented = (method: string) =>
    new MongoDBOIDCError(`Not implemented: body.${method}`, {
      codeName: 'HTTPBodyShimNotImplemented',
    });
  const { body, clone } = response;
  if (streamIsNodeReadable(body)) {
    let webStream: ReadableStream | undefined;
    const toWeb = () =>
      webStream ?? (body.constructor as typeof Readable).toWeb?.(body);
    // Provide ReadableStream methods that may be used by openid-client
    Object.assign(
      body,
      {
        locked: false,
        cancel() {
          if (webStream) return webStream.cancel();
          body.resume();
        },
        getReader(...args: Parameters<ReadableStream['getReader']>) {
          if ((webStream = toWeb())) return webStream.getReader(...args);

          throw notImplemented('getReader');
        },
        pipeThrough(...args: Parameters<ReadableStream['pipeThrough']>) {
          if ((webStream = toWeb())) return webStream.pipeThrough(...args);
          throw notImplemented('pipeThrough');
        },
        pipeTo(...args: Parameters<ReadableStream['pipeTo']>) {
          if ((webStream = toWeb())) return webStream.pipeTo(...args);

          throw notImplemented('pipeTo');
        },
        tee(...args: Parameters<ReadableStream['tee']>) {
          if ((webStream = toWeb())) return webStream.tee(...args);
          throw notImplemented('tee');
        },
        values(...args: Parameters<ReadableStream['values']>) {
          if ((webStream = toWeb())) return webStream.values(...args);
          throw notImplemented('values');
        },
      },
      body
    );
    Object.assign(response, {
      clone: function (this: Response): Response {
        // node-fetch replaces `.body` on `.clone()` on *both*
        // the original and the cloned Response objects
        const cloned = clone.call(this);
        nodeFetchCompat(this);
        return nodeFetchCompat(cloned);
      },
    });
  }

  return response;
}
