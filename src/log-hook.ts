import type { MongoDBOIDCLogEventsMap, TypedEventEmitter } from './types';

/** @public */
export interface MongoLogWriter {
  debug?(
    c: string,
    id: unknown,
    ctx: string,
    msg: string,
    attr?: unknown,
    level?: 1 | 2 | 3 | 4 | 5
  ): void;
  info(c: string, id: unknown, ctx: string, msg: string, attr?: unknown): void;
  warn(c: string, id: unknown, ctx: string, msg: string, attr?: unknown): void;
  error(c: string, id: unknown, ctx: string, msg: string, attr?: unknown): void;
  mongoLogId(this: void, id: number): unknown;
}

/**
 * Connect a log event emitter instance such as the one attached to a
 * `MongoDBOIDCPlugin` instance to a log writer that follows the format
 * provided by the `mongodb-log-writer` npm package.
 *
 * @public
 */
export function hookLoggerToMongoLogWriter(
  emitter: TypedEventEmitter<MongoDBOIDCLogEventsMap>,
  log: MongoLogWriter,
  contextPrefix: string
): void {
  const { mongoLogId } = log;

  emitter.on('mongodb-oidc-plugin:local-redirect-accessed', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_001),
      `${contextPrefix}-oidc`,
      'Local redirect accessed',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:oidc-callback-accepted', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_002),
      `${contextPrefix}-oidc`,
      'OIDC callback accepted',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:oidc-callback-rejected', (ev) => {
    log.warn(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_003),
      `${contextPrefix}-oidc`,
      'OIDC callback rejected',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:unknown-url-accessed', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_004),
      `${contextPrefix}-oidc`,
      'Unknown URL accessed',
      {
        ...ev,
        // strip away any query/search string (after ?) in the URL
        path: new URL(ev.path, 'http://dummy/').pathname,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:local-listen-started', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_005),
      `${contextPrefix}-oidc`,
      'Started listening on local server',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:local-listen-failed', (ev) => {
    log.error(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_006),
      `${contextPrefix}-oidc`,
      'Failed to listen on local server',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:local-listen-succeeded', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_007),
      `${contextPrefix}-oidc`,
      'Successfully listening on local server',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:local-server-close', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_008),
      `${contextPrefix}-oidc`,
      'Local server closed',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:open-browser', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_009),
      `${contextPrefix}-oidc`,
      'Opening browser',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:open-browser-complete', () => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_025),
      `${contextPrefix}-oidc`,
      'Successfully opened browser'
    );
  });

  emitter.on('mongodb-oidc-plugin:notify-device-flow', () => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_010),
      `${contextPrefix}-oidc`,
      'Notifying user about device flow authentication'
    );
  });

  emitter.on('mongodb-oidc-plugin:auth-attempt-started', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_011),
      `${contextPrefix}-oidc`,
      'Authentication attempt started',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:auth-attempt-failed', (ev) => {
    log.warn(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_012),
      `${contextPrefix}-oidc`,
      'Authentication attempt failed',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:auth-attempt-succeeded', () => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_013),
      `${contextPrefix}-oidc`,
      'Authentication attempt succeeded'
    );
  });

  emitter.on('mongodb-oidc-plugin:refresh-failed', (ev) => {
    log.warn(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_014),
      `${contextPrefix}-oidc`,
      'Token refresh failed',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:skip-auth-attempt', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_015),
      `${contextPrefix}-oidc`,
      'Skipping explicit authentication attempt',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:auth-failed', (ev) => {
    log.warn(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_016),
      `${contextPrefix}-oidc`,
      'Authentication failed',
      {
        ...ev,
      }
    );
  });

  emitter.on(
    'mongodb-oidc-plugin:auth-succeeded',
    ({ tokenType, refreshToken, expiresAt, passIdTokenAsAccessToken }) => {
      log.info(
        'OIDC-PLUGIN',
        mongoLogId(1_002_000_017),
        `${contextPrefix}-oidc`,
        'Authentication succeeded',
        {
          tokenType,
          refreshToken,
          expiresAt,
          passIdTokenAsAccessToken,
        }
      );
    }
  );

  emitter.on('mongodb-oidc-plugin:refresh-skipped', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_026),
      `${contextPrefix}-oidc`,
      'Token refresh attempt skipped',
      { ...ev }
    );
  });

  emitter.on('mongodb-oidc-plugin:refresh-started', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_018),
      `${contextPrefix}-oidc`,
      'Token refresh attempt started',
      { ...ev }
    );
  });

  emitter.on('mongodb-oidc-plugin:refresh-succeeded', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_019),
      `${contextPrefix}-oidc`,
      'Token refresh attempt succeeded',
      { ...ev }
    );
  });

  emitter.on('mongodb-oidc-plugin:deserialization-failed', (ev) => {
    log.error(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_020),
      `${contextPrefix}-oidc`,
      'State deserialization failed',
      {
        ...ev,
      }
    );
  });

  emitter.on('mongodb-oidc-plugin:destroyed', () => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_021),
      `${contextPrefix}-oidc`,
      'Destroyed OIDC plugin instance'
    );
  });

  emitter.on('mongodb-oidc-plugin:missing-id-token', () => {
    log.warn(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_022),
      `${contextPrefix}-oidc`,
      'Missing ID token in IdP response'
    );
  });

  emitter.on('mongodb-oidc-plugin:outbound-http-request', (ev) => {
    log.debug?.(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_023),
      `${contextPrefix}-oidc`,
      'Outbound HTTP request',
      { url: redactUrl(ev.url) }
    );
  });

  emitter.on('mongodb-oidc-plugin:inbound-http-request', (ev) => {
    log.debug?.(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_024),
      `${contextPrefix}-oidc`,
      'Inbound HTTP request',
      { url: redactUrl(ev.url) }
    );
  });

  emitter.on('mongodb-oidc-plugin:state-updated', (ev) => {
    log.info(
      'OIDC-PLUGIN',
      mongoLogId(1_002_000_027),
      `${contextPrefix}-oidc`,
      'Updated internal token store state',
      { ...ev }
    );
  });
}

function redactUrl(url: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return '<Invalid URL>';
  }
  for (const key of [...parsed.searchParams.keys()])
    parsed.searchParams.set(key, '');
  return parsed.toString();
}
