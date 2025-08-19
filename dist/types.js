"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MongoDBOIDCError = void 0;
/** @internal */
const MongoDBOIDCErrorTag = Symbol.for('@@mdb.oidcplugin.MongoDBOIDCErrorTag');
/** @public */
class MongoDBOIDCError extends Error {
    /** @internal */
    [MongoDBOIDCErrorTag] = true;
    codeName;
    constructor(message, { cause, codeName }) {
        super(message, { cause });
        this.codeName = `MongoDBOIDC${codeName}`;
    }
    static isMongoDBOIDCError(value) {
        return (
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        value && typeof value === 'object' && value[MongoDBOIDCErrorTag]);
    }
}
exports.MongoDBOIDCError = MongoDBOIDCError;
//# sourceMappingURL=types.js.map