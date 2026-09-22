/**
 * Config type + default-filling logic.
 *
 * TS models the two tri-state bool knobs (requestIncludeContext, hashCacheKey)
 * as `boolean | undefined`: undefined means "use default", an explicit
 * `false` is respected as opt-out.
 */

import type { Cache } from './cache.js'
import { newLRUCache } from './cache.js'
import type { MetricsCollector } from './metrics.js'
import { noopMetrics } from './metrics.js'
import type { ErrorMapperFn } from './errors.js'
import { defaultErrorMapper } from './errors.js'

/** Console-shaped logger the SDK writes diagnostics to. */
export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void
  info?(message: string, meta?: Record<string, unknown>): void
  warn?(message: string, meta?: Record<string, unknown>): void
  error?(message: string, meta?: Record<string, unknown>): void
}

/** Default logger — a thin wrapper over console so pino/winston can drop in. */
export const consoleLogger: Logger = {
  debug(message, meta) {
    if (meta === undefined) console.debug(message)
    else console.debug(message, meta)
  },
  info(message, meta) {
    if (meta === undefined) console.info(message)
    else console.info(message, meta)
  },
  warn(message, meta) {
    if (meta === undefined) console.warn(message)
    else console.warn(message, meta)
  },
  error(message, meta) {
    if (meta === undefined) console.error(message)
    else console.error(message, meta)
  },
}

/** Default values, exported so callers can reference / compose. */
export const DEFAULT_LRU_CACHE_SIZE = 10_000
export const DEFAULT_HTTP_TIMEOUT_MS = 5_000
export const DEFAULT_SESSION_TTL_MS = 30_000
export const DEFAULT_BOT_TTL_MS = 60_000
export const DEFAULT_API_KEY_TTL_MS = 60_000
export const DEFAULT_NEGATIVE_TTL_MS = 5_000

/**
 * Config holds shared configuration passed to every verifier. Only baseUrl is
 * required; everything else has a safe default filled in by applyDefaults.
 */
export interface Config {
  /** Required. octo-server base URL, e.g. https://octo-server:8090. */
  baseUrl: string
  /** Per-service credential for the new Bot Resolve endpoint. */
  serviceToken?: string
  /** Fetch implementation. Defaults to globalThis.fetch (Node 20+). */
  fetch?: typeof globalThis.fetch
  /** Cache backend. Defaults to newLRUCache(10_000). */
  cache?: Cache
  /** Metrics sink. Defaults to noopMetrics. */
  metrics?: MetricsCollector
  /** Logger. Defaults to consoleLogger. */
  logger?: Logger
  /** Middleware error mapper. Defaults to defaultErrorMapper. */
  errorMapper?: ErrorMapperFn

  /** Per-request timeout in ms. Defaults to 5000. */
  timeoutMs?: number

  /** Session realm cache TTL. Defaults to 30_000 (SSO revocation window). */
  sessionTtlMs?: number
  /** Bot realm cache TTL. Defaults to 60_000. */
  botTtlMs?: number
  /** API-key realm cache TTL. Defaults to 60_000. */
  apiKeyTtlMs?: number
  /** Negative-result cache TTL. Defaults to 5_000. */
  negativeTtlMs?: number

  /**
   * Whether the session / api-key verifiers append ?include=context to their
   * POST. Defaults to `true`. Set to `false` to opt out explicitly.
   * Bot verifier ignores this field.
   */
  requestIncludeContext?: boolean

  /**
   * Whether to SHA-256 hash raw tokens before using them as cache keys.
   * Defaults to `true`. Set to `false` only for local debugging.
   */
  hashCacheKey?: boolean
}

/**
 * ResolvedConfig is a Config after applyDefaults has run — every optional
 * field is populated. Verifier internals should reference this type rather
 * than the user-facing Config so they can trust every field exists.
 */
export interface ResolvedConfig {
  baseUrl: string
  fetch: typeof globalThis.fetch
  cache: Cache
  metrics: MetricsCollector
  logger: Logger
  errorMapper: ErrorMapperFn
  timeoutMs: number
  sessionTtlMs: number
  botTtlMs: number
  apiKeyTtlMs: number
  negativeTtlMs: number
  requestIncludeContext: boolean
  hashCacheKey: boolean
}

/**
 * applyDefaults mutates cfg in place to fill unset fields with the package
 * defaults. Returns cfg cast to ResolvedConfig so downstream code has a fully
 * populated shape.
 *
 * Idempotent — safe to call from every verifier constructor. The three
 * verifiers built from the same *Config share a single cache / metrics / etc.
 *
 * Throws if cfg is nullish so misconfiguration is caught at startup rather
 * than on the first request.
 */
export function applyDefaults(cfg: Config): ResolvedConfig {
  if (cfg == null) {
    throw new Error('octoauth: Config must not be null')
  }
  if (!cfg.baseUrl || typeof cfg.baseUrl !== 'string') {
    throw new Error('octoauth: Config.baseUrl is required')
  }
  if (cfg.fetch === undefined) {
    // Node 20+ has global fetch. Deliberately capture the reference at
    // resolution time so user's later monkey-patches don't unexpectedly apply.
    if (typeof globalThis.fetch !== 'function') {
      throw new Error(
        'octoauth: globalThis.fetch is not available; pass Config.fetch explicitly',
      )
    }
    cfg.fetch = globalThis.fetch.bind(globalThis)
  }
  if (cfg.cache === undefined) cfg.cache = newLRUCache(DEFAULT_LRU_CACHE_SIZE)
  if (cfg.metrics === undefined) cfg.metrics = noopMetrics
  if (cfg.logger === undefined) cfg.logger = consoleLogger
  if (cfg.errorMapper === undefined) cfg.errorMapper = defaultErrorMapper
  if (cfg.timeoutMs === undefined) cfg.timeoutMs = DEFAULT_HTTP_TIMEOUT_MS
  // TTL fields: undefined OR <= 0 → default. Matches Go SDK's applyDefaults
  // (config.go), which treats TTL == 0 as "use default". Without this coercion
  // an explicit `sessionTtlMs: 0` would flow into cache.set() and, per the
  // cache contract (ttlMs <= 0 → no expiry), create a permanent auth cache
  // — an unbounded SSO-revocation window.
  if (cfg.sessionTtlMs === undefined || cfg.sessionTtlMs <= 0) {
    cfg.sessionTtlMs = DEFAULT_SESSION_TTL_MS
  }
  if (cfg.botTtlMs === undefined || cfg.botTtlMs <= 0) {
    cfg.botTtlMs = DEFAULT_BOT_TTL_MS
  }
  if (cfg.apiKeyTtlMs === undefined || cfg.apiKeyTtlMs <= 0) {
    cfg.apiKeyTtlMs = DEFAULT_API_KEY_TTL_MS
  }
  if (cfg.negativeTtlMs === undefined || cfg.negativeTtlMs <= 0) {
    cfg.negativeTtlMs = DEFAULT_NEGATIVE_TTL_MS
  }
  // undefined → default true; explicit false is respected.
  if (cfg.requestIncludeContext === undefined) cfg.requestIncludeContext = true
  if (cfg.hashCacheKey === undefined) cfg.hashCacheKey = true
  return cfg as ResolvedConfig
}
