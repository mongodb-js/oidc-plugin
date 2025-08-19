"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hookLoggerToMongoLogWriter = hookLoggerToMongoLogWriter;
/**
 * Connect a log event emitter instance such as the one attached to a
 * `MongoDBOIDCPlugin` instance to a log writer that follows the format
 * provided by the `mongodb-log-writer` npm package.
 *
 * @public
 */
function hookLoggerToMongoLogWriter(emitter, log, contextPrefix) {
    const { mongoLogId } = log;
    emitter.on('mongodb-oidc-plugin:local-redirect-accessed', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_001), `${contextPrefix}-oidc`, 'Local redirect accessed', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:oidc-callback-accepted', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_002), `${contextPrefix}-oidc`, 'OIDC callback accepted', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:oidc-callback-rejected', (ev) => {
        log.warn('OIDC-PLUGIN', mongoLogId(1_002_000_003), `${contextPrefix}-oidc`, 'OIDC callback rejected', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:unknown-url-accessed', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_004), `${contextPrefix}-oidc`, 'Unknown URL accessed', {
            ...ev,
            // strip away any query/search string (after ?) in the URL
            path: new URL(ev.path, 'http://dummy/').pathname,
        });
    });
    emitter.on('mongodb-oidc-plugin:local-listen-started', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_005), `${contextPrefix}-oidc`, 'Started listening on local server', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:local-listen-resolved-hostname', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_028), `${contextPrefix}-oidc`, 'Resolved hostnames for local server', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:local-listen-failed', (ev) => {
        log.error('OIDC-PLUGIN', mongoLogId(1_002_000_006), `${contextPrefix}-oidc`, 'Failed to listen on local server', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:local-listen-succeeded', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_007), `${contextPrefix}-oidc`, 'Successfully listening on local server', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:local-server-close', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_008), `${contextPrefix}-oidc`, 'Local server closed', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:open-browser', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_009), `${contextPrefix}-oidc`, 'Opening browser', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:open-browser-complete', () => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_025), `${contextPrefix}-oidc`, 'Successfully opened browser');
    });
    emitter.on('mongodb-oidc-plugin:notify-device-flow', () => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_010), `${contextPrefix}-oidc`, 'Notifying user about device flow authentication');
    });
    emitter.on('mongodb-oidc-plugin:auth-attempt-started', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_011), `${contextPrefix}-oidc`, 'Authentication attempt started', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:auth-attempt-failed', (ev) => {
        log.warn('OIDC-PLUGIN', mongoLogId(1_002_000_012), `${contextPrefix}-oidc`, 'Authentication attempt failed', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:auth-attempt-succeeded', () => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_013), `${contextPrefix}-oidc`, 'Authentication attempt succeeded');
    });
    emitter.on('mongodb-oidc-plugin:refresh-failed', (ev) => {
        log.warn('OIDC-PLUGIN', mongoLogId(1_002_000_014), `${contextPrefix}-oidc`, 'Token refresh failed', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:skip-auth-attempt', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_015), `${contextPrefix}-oidc`, 'Skipping explicit authentication attempt', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:auth-failed', (ev) => {
        log.warn('OIDC-PLUGIN', mongoLogId(1_002_000_016), `${contextPrefix}-oidc`, 'Authentication failed', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:auth-succeeded', ({ authStateId, tokenType, refreshToken, expiresAt, passIdTokenAsAccessToken, forceRefreshOrReauth, willRetryWithForceRefreshOrReauth, tokenSetId, }) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_017), `${contextPrefix}-oidc`, 'Authentication succeeded', {
            authStateId,
            tokenType,
            refreshToken,
            expiresAt,
            passIdTokenAsAccessToken,
            forceRefreshOrReauth,
            willRetryWithForceRefreshOrReauth,
            tokenSetId,
        });
    });
    emitter.on('mongodb-oidc-plugin:refresh-skipped', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_026), `${contextPrefix}-oidc`, 'Token refresh attempt skipped', { ...ev });
    });
    emitter.on('mongodb-oidc-plugin:refresh-started', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_018), `${contextPrefix}-oidc`, 'Token refresh attempt started', { ...ev });
    });
    emitter.on('mongodb-oidc-plugin:refresh-succeeded', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_019), `${contextPrefix}-oidc`, 'Token refresh attempt succeeded', { ...ev });
    });
    emitter.on('mongodb-oidc-plugin:deserialization-failed', (ev) => {
        log.error('OIDC-PLUGIN', mongoLogId(1_002_000_020), `${contextPrefix}-oidc`, 'State deserialization failed', {
            ...ev,
        });
    });
    emitter.on('mongodb-oidc-plugin:request-token-started', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_029), `${contextPrefix}-oidc`, 'Request token started', { ...ev });
    });
    emitter.on('mongodb-oidc-plugin:request-token-ended', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_030), `${contextPrefix}-oidc`, 'Request token finished', { ...ev });
    });
    emitter.on('mongodb-oidc-plugin:discarding-token-set', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_031), `${contextPrefix}-oidc`, 'Discarding token set', { ...ev });
    });
    emitter.on('mongodb-oidc-plugin:destroyed', () => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_021), `${contextPrefix}-oidc`, 'Destroyed OIDC plugin instance');
    });
    emitter.on('mongodb-oidc-plugin:missing-id-token', () => {
        log.warn('OIDC-PLUGIN', mongoLogId(1_002_000_022), `${contextPrefix}-oidc`, 'Missing ID token in IdP response');
    });
    emitter.on('mongodb-oidc-plugin:outbound-http-request', (ev) => {
        log.debug?.('OIDC-PLUGIN', mongoLogId(1_002_000_023), `${contextPrefix}-oidc`, 'Outbound HTTP request', { url: redactUrl(ev.url) });
    });
    emitter.on('mongodb-oidc-plugin:inbound-http-request', (ev) => {
        log.debug?.('OIDC-PLUGIN', mongoLogId(1_002_000_024), `${contextPrefix}-oidc`, 'Inbound HTTP request', { url: redactUrl(ev.url) });
    });
    emitter.on('mongodb-oidc-plugin:outbound-http-request-completed', (ev) => {
        log.debug?.('OIDC-PLUGIN', mongoLogId(1_002_000_032), `${contextPrefix}-oidc`, 'Outbound HTTP request completed', { ...ev, url: redactUrl(ev.url) });
    });
    emitter.on('mongodb-oidc-plugin:outbound-http-request-failed', (ev) => {
        log.debug?.('OIDC-PLUGIN', mongoLogId(1_002_000_033), `${contextPrefix}-oidc`, 'Outbound HTTP request failed', { ...ev, url: redactUrl(ev.url) });
    });
    emitter.on('mongodb-oidc-plugin:state-updated', (ev) => {
        log.info('OIDC-PLUGIN', mongoLogId(1_002_000_027), `${contextPrefix}-oidc`, 'Updated internal token store state', { ...ev });
    });
}
function redactUrl(url) {
    let parsed;
    try {
        parsed = new URL(url);
    }
    catch {
        return '<Invalid URL>';
    }
    for (const key of [...parsed.searchParams.keys()])
        parsed.searchParams.set(key, '');
    return parsed.toString();
}
//# sourceMappingURL=log-hook.js.map