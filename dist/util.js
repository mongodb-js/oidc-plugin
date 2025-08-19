"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TokenSet = void 0;
exports.throwIfAborted = throwIfAborted;
exports.withAbortCheck = withAbortCheck;
exports.timeoutSignal = timeoutSignal;
exports.withLock = withLock;
exports.normalizeObject = normalizeObject;
exports.validateSecureHTTPUrl = validateSecureHTTPUrl;
exports.errorString = errorString;
exports.getRefreshTokenId = getRefreshTokenId;
exports.improveHTTPResponseBasedError = improveHTTPResponseBasedError;
exports.streamIsNodeReadable = streamIsNodeReadable;
exports.nodeFetchCompat = nodeFetchCompat;
const types_1 = require("./types");
const crypto_1 = require("crypto");
class AbortError extends Error {
    constructor() {
        super('The operation was aborted');
    }
}
function throwIfAborted(signal) {
    if (signal?.aborted)
        throw signal.reason ?? new AbortError();
}
async function withAbortCheck(signal, fn) {
    const signalCheck = () => throwIfAborted(signal);
    let reject;
    const signalPromise = new Promise((resolve, rej) => {
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
    }
    finally {
        signal?.removeEventListener('abort', listener);
    }
}
// AbortSignal.timeout, but consistently .unref()ed
function timeoutSignal(ms) {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), ms).unref();
    return controller.signal;
}
// Ensure that only one call to the target `fn` is active at a time.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function withLock(fn) {
    // `lock` represents the completion of the current call to fn(), if any.
    let lock = Promise.resolve();
    return (...args) => {
        const result = lock
            .then(() => fn(...args))
            .finally(() => {
            lock = Promise.resolve();
        });
        lock = result.catch(() => {
            /* handled by caller */
        });
        return result;
    };
}
// Normalize JS objects by sorting keys so that {a:1,b:2} and {b:2,a:1} are equivalent.
// eslint-disable-next-line @typescript-eslint/ban-types
function normalizeObject(obj) {
    return Object.fromEntries(Object.entries(obj).sort());
}
function isURL(url) {
    return Object.prototype.toString.call(url).toLowerCase() === '[object url]';
}
// Throws if the url does not refer to an https: endpoint or a local endpoint, or null or undefined.
function validateSecureHTTPUrl(url, diagnosticId) {
    try {
        // eslint-disable-next-line eqeqeq
        if (url == null)
            return 'http-disallowed';
        if (typeof url !== 'string' && !isURL(url))
            throw new Error(`Expected string or URL object, got ${typeof url} instead`);
        const parsed = isURL(url) ? url : new URL(url);
        if (parsed.protocol === 'https:')
            return 'http-disallowed';
        if (parsed.protocol !== 'http:') {
            throw new Error(`Unknown protocol '${parsed.protocol}' '${String(url)}'`);
        }
        if (!/^(\[::1\]|127(\.\d+){3}|localhost)$/.test(parsed.hostname)) {
            throw new Error(`Need to specify https: when accessing non-local URL '${String(url)}'`);
        }
        return 'http-allowed';
    }
    catch (err) {
        if (!err ||
            typeof err !== 'object' ||
            !('message' in err) ||
            typeof err.message !== 'string') {
            throw err;
        }
        err.message += ` (validating: ${diagnosticId})`;
        throw err;
    }
}
function errorString(err) {
    if (!err ||
        typeof err !== 'object' ||
        !('message' in err) ||
        typeof err.message !== 'string') {
        return String(err);
    }
    const cause = getCause(err);
    let { message } = err;
    if (cause) {
        const causeMessage = errorString(cause);
        if (!message.includes(causeMessage) &&
            !causeMessage.match(/^\[object.+\]$/i))
            message += ` (caused by: ${causeMessage})`;
    }
    return message;
}
const salt = (0, crypto_1.randomBytes)(16);
function getRefreshTokenId(token) {
    if (!token)
        return null;
    // Add a prefix to indicate that this isn't an actual refresh token,
    // that might unnecessarily worry users
    return ('debugid:' + (0, crypto_1.createHash)('sha256').update(salt).update(token).digest('hex'));
}
class TokenSet {
    response;
    expiresAt;
    constructor(response, expiresAt) {
        this.response = response;
        this.expiresAt =
            expiresAt ??
                (() => {
                    const expiresIn = this.response.expiresIn();
                    return expiresIn
                        ? Math.floor(Date.now() / 1000) + expiresIn
                        : undefined;
                })();
    }
    get refreshToken() {
        return this.response.refresh_token;
    }
    get accessToken() {
        return this.response.access_token;
    }
    get idToken() {
        return this.response.id_token;
    }
    get idTokenClaims() {
        return this.response.claims();
    }
    get tokenType() {
        return this.response.token_type;
    }
    // Explicitly expressing the return type of this function is a bit awkward,
    // and since it is only consumed by `fromSerialized`, it's fine to leave it inferred.
    serialize() {
        const expiresIn = this.response.expiresIn();
        const claims = this.response.claims();
        return {
            ...this.response,
            claims: claims ? { ...claims } : undefined,
            expiresAt: this.expiresAt ??
                (expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : undefined),
            expiresIn: undefined,
        };
    }
    static fromSerialized(serialized) {
        const helpers = {
            claims: () => serialized.claims,
            expiresIn: () => serialized.expiresAt &&
                Math.max(0, serialized.expiresAt - Math.floor(Date.now() / 1000)),
        };
        return new this(Object.assign({ ...serialized }, helpers), serialized.expiresAt);
    }
    // Identify a token set based on a hash of its contents
    stableId() {
        const { access_token, id_token, refresh_token, token_type } = this.response;
        return (0, crypto_1.createHash)('sha256')
            .update(JSON.stringify({
            access_token,
            id_token,
            refresh_token,
            token_type,
            expires_at: this.expiresAt,
        }))
            .digest('hex');
    }
}
exports.TokenSet = TokenSet;
function getCause(err) {
    if (err &&
        typeof err === 'object' &&
        'cause' in err &&
        err.cause &&
        typeof err.cause === 'object') {
        return err.cause;
    }
}
// openid-client@6.x has reduced error messages for HTTP errors significantly, reducing e.g.
// an HTTP error to just a simple 'unexpect HTTP response status code' message, without
// further diagnostic information. So if the `cause` of an `err` object is a fetch `Response`
// object, we try to throw a more helpful error.
async function improveHTTPResponseBasedError(err) {
    // Note: `err.cause` can either be an `Error` object itself, or a `Response`, or a JSON HTTP response body
    const cause = getCause(err);
    if (cause) {
        try {
            const statusObject = 'status' in cause ? cause : err;
            if (!statusObject.status)
                return err;
            let body = '';
            try {
                if ('text' in cause && typeof cause.text === 'function')
                    body = await cause.text(); // Handle the `Response` case
            }
            catch {
                // ignore
            }
            let errorMessageFromBody = '';
            try {
                let parsed = cause;
                try {
                    parsed = JSON.parse(body);
                }
                catch {
                    // ignore, and maybe `parsed` already contains the parsed JSON body anyway
                }
                errorMessageFromBody =
                    ': ' +
                        [parsed.error, parsed.error_description]
                            .filter(Boolean)
                            .map(String)
                            .join(', ');
            }
            catch {
                // ignore
            }
            if (!errorMessageFromBody)
                errorMessageFromBody = `: ${body}`;
            const statusTextInsert = 'statusText' in statusObject
                ? `(${String(statusObject.statusText)})`
                : '';
            return new types_1.MongoDBOIDCError(`${errorString(err)}: caused by HTTP response ${String(statusObject.status)} ${statusTextInsert}${errorMessageFromBody}`, { codeName: 'HTTPResponseError', cause: err });
        }
        catch {
            return err;
        }
    }
    return err;
}
// Check whether converting a Node.js `Readable` stream to a web `ReadableStream`
// is possible. We use this for compatibility with fetch() implementations that
// return Node.js `Readable` streams like node-fetch.
function streamIsNodeReadable(stream) {
    return !!(stream &&
        typeof stream === 'object' &&
        'pipe' in stream &&
        typeof stream.pipe === 'function' &&
        (!('cancel' in stream) || !stream.cancel));
}
function nodeFetchCompat(response) {
    const notImplemented = (method) => new types_1.MongoDBOIDCError(`Not implemented: body.${method}`, {
        codeName: 'HTTPBodyShimNotImplemented',
    });
    const { body, clone } = response;
    if (streamIsNodeReadable(body)) {
        let webStream;
        const toWeb = () => webStream ?? body.constructor.toWeb?.(body);
        // Provide ReadableStream methods that may be used by openid-client
        Object.assign(body, {
            locked: false,
            cancel() {
                if (webStream)
                    return webStream.cancel();
                body.resume();
            },
            getReader(...args) {
                if ((webStream = toWeb()))
                    return webStream.getReader(...args);
                throw notImplemented('getReader');
            },
            pipeThrough(...args) {
                if ((webStream = toWeb()))
                    return webStream.pipeThrough(...args);
                throw notImplemented('pipeThrough');
            },
            pipeTo(...args) {
                if ((webStream = toWeb()))
                    return webStream.pipeTo(...args);
                throw notImplemented('pipeTo');
            },
            tee(...args) {
                if ((webStream = toWeb()))
                    return webStream.tee(...args);
                throw notImplemented('tee');
            },
            values(...args) {
                if ((webStream = toWeb()))
                    return webStream.values(...args);
                throw notImplemented('values');
            },
        }, body);
        Object.assign(response, {
            clone: function () {
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
//# sourceMappingURL=util.js.map