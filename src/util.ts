import type { OIDCAbortSignal } from './types';

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

export const AbortController =
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  globalThis.AbortController ?? require('abort-controller').AbortController;
export const AbortSignal =
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  globalThis.AbortSignal ?? require('abort-controller').AbortSignal;

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

// Throws if the url does not refer to an https: endpoint or a local endpoint, or null or undefined.
export function validateSecureHTTPUrl(
  url: unknown,
  diagnosticId: string
): void {
  try {
    // eslint-disable-next-line eqeqeq
    if (url == null) return;
    if (typeof url !== 'string')
      throw new Error(`Expected string, got ${typeof url} instead`);
    const parsed = new URL(url);
    if (parsed.protocol === 'https:') return;
    if (parsed.protocol !== 'http:') {
      throw new Error(`Unknown protocol '${parsed.protocol}' '${url}'`);
    }
    if (!/^(\[::1\]|127(\.\d+){3}|localhost)$/.test(parsed.hostname)) {
      throw new Error(
        `Need to specify https: when accessing non-local URL '${url}'`
      );
    }
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
