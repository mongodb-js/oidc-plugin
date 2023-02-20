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
