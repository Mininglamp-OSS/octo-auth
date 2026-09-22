/**
 * @mininglamp-oss/octo-auth — public entry.
 *
 * Re-exports the verifier / principal / errors / config / cache / metrics /
 * extract surface. Subpath exports:
 *
 *   - `/middleware/express`  — express middleware factory
 *   - `/middleware/hocuspocus` — hocuspocus onAuthenticate hook
 *   - `/internal-helpers`    — service-to-service token helpers
 *   - `/layer2`              — short-lived JWT issue/verify
 *
 * Ambient Express.Request augmentation ships automatically when this module
 * is imported (see `types-ext.d.ts`).
 */

// Verifier core
export {
  KindSession,
  KindBot,
  KindAPIKey,
  PrefixUK,
  PrefixBF,
  PrefixApp,
  MinAPIKeyLength,
  classifyCredential,
  newMultiVerifier,
  type PrincipalKind,
  type ContextKind,
  type PrincipalContext,
  type Principal,
  type Credential,
  type VerifyOptions,
  type Verifier,
  type MultiVerifier,
} from './verifier.js'

// Errors
export {
  OctoAuthError,
  defaultErrorMapper,
  BODY_UNAUTHORIZED,
  BODY_DISABLED,
  BODY_UPSTREAM_UNAVAILABLE,
  BODY_FORBIDDEN,
  BODY_INVALID_REQUEST,
  BODY_INTERNAL,
  type ErrorKind,
  type OctoAuthErrorOptions,
  type ErrorMapperFn,
  type ErrorMapperResult,
} from './errors.js'

// Config
export {
  applyDefaults,
  consoleLogger,
  DEFAULT_LRU_CACHE_SIZE,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_SESSION_TTL_MS,
  DEFAULT_BOT_TTL_MS,
  DEFAULT_API_KEY_TTL_MS,
  DEFAULT_NEGATIVE_TTL_MS,
  type Config,
  type ResolvedConfig,
  type Logger,
} from './config.js'

// Cache
export {
  hashCacheKey,
  newLRUCache,
  type Cache,
} from './cache.js'

// Metrics
export {
  noopMetrics,
  type MetricsCollector,
  type VerifyResult,
} from './metrics.js'

// Extract
export {
  extractCredential,
  validateAPIKey,
  validateBotToken,
  HeaderAuthorization,
  HeaderToken,
  BearerScheme,
  type HeadersLike,
  type RequestLike,
} from './extract.js'

// Principal clone helper
export { clonePrincipal } from './principal-clone.js'

// Verifier implementations
export { newSessionVerifier } from './session-verifier.js'
export { newBotTokenVerifier } from './bot-token-verifier.js'
export { newUserKeyVerifier } from './user-key-verifier.js'
export { newFullMultiVerifier } from './full-multi-verifier.js'
export {
  newBotResolver,
  type BotResolver,
  type BotResolveMode,
  type ResolveRequest,
  type ResolvedPrincipal,
  type ResolvedIdentity,
  type ResolvedDelegation,
} from './resolver.js'

// Ambient Express.Request augmentation (empty runtime import; side-effect on types only).
import './types-ext.js'
