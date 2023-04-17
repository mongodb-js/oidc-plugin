export { createMongoDBOIDCPlugin } from './api';
export type {
  MongoDBOIDCPlugin,
  MongoDBOIDCPluginOptions,
  AuthFlowType,
  DeviceFlowInformation,
  OpenBrowserOptions,
  OpenBrowserReturnType,
  RedirectServerRequestHandler,
  RedirectServerRequestInfo,
} from './api';

export type {
  TypedEventEmitter,
  OIDCClientInfo,
  OIDCRefreshFunction,
  OIDCRequestFunction,
  OIDCMechanismServerStep1,
  OIDCRequestTokenResult,
  OIDCAbortSignal,
  MongoDBOIDCError,
  MongoDBOIDCLogEventsMap,
} from './types';

export { hookLoggerToMongoLogWriter, MongoLogWriter } from './log-hook';
