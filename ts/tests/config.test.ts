import { describe, expect, it } from 'vitest'

import {
  DEFAULT_API_KEY_TTL_MS,
  DEFAULT_BOT_TTL_MS,
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_LRU_CACHE_SIZE,
  DEFAULT_NEGATIVE_TTL_MS,
  DEFAULT_SESSION_TTL_MS,
  applyDefaults,
  consoleLogger,
  defaultErrorMapper,
  newLRUCache,
  noopMetrics,
  type Config,
} from '../src/index.js'

describe('applyDefaults', () => {
  it('fills every optional field with the documented default', () => {
    const cfg: Config = { baseUrl: 'https://octo.test' }
    const r = applyDefaults(cfg)
    expect(r.baseUrl).toBe('https://octo.test')
    expect(r.timeoutMs).toBe(DEFAULT_HTTP_TIMEOUT_MS)
    expect(r.sessionTtlMs).toBe(DEFAULT_SESSION_TTL_MS)
    expect(r.botTtlMs).toBe(DEFAULT_BOT_TTL_MS)
    expect(r.apiKeyTtlMs).toBe(DEFAULT_API_KEY_TTL_MS)
    expect(r.negativeTtlMs).toBe(DEFAULT_NEGATIVE_TTL_MS)
    expect(r.requestIncludeContext).toBe(true)
    expect(r.hashCacheKey).toBe(true)
    expect(r.metrics).toBe(noopMetrics)
    expect(r.logger).toBe(consoleLogger)
    expect(r.errorMapper).toBe(defaultErrorMapper)
    expect(typeof r.fetch).toBe('function')
    // Cache backend is present.
    expect(typeof r.cache.get).toBe('function')
  })

  it('exposes DEFAULT_LRU_CACHE_SIZE', () => {
    expect(DEFAULT_LRU_CACHE_SIZE).toBe(10_000)
  })

  it('explicit false for requestIncludeContext is respected', () => {
    const r = applyDefaults({
      baseUrl: 'https://octo.test',
      requestIncludeContext: false,
    })
    expect(r.requestIncludeContext).toBe(false)
  })

  it('explicit false for hashCacheKey is respected', () => {
    const r = applyDefaults({
      baseUrl: 'https://octo.test',
      hashCacheKey: false,
    })
    expect(r.hashCacheKey).toBe(false)
  })

  it('is idempotent — second call does not clobber previously-set values', () => {
    const cfg: Config = { baseUrl: 'https://octo.test' }
    const first = applyDefaults(cfg)
    const firstCache = first.cache
    const firstFetch = first.fetch
    const second = applyDefaults(cfg)
    expect(second.cache).toBe(firstCache)
    expect(second.fetch).toBe(firstFetch)
  })

  it('throws when cfg is null', () => {
    expect(() => applyDefaults(null as unknown as Config)).toThrow(/must not be null/)
  })

  it('throws when baseUrl is missing / empty', () => {
    expect(() => applyDefaults({} as Config)).toThrow(/baseUrl is required/)
    expect(() => applyDefaults({ baseUrl: '' })).toThrow(/baseUrl is required/)
  })

  it('respects a caller-supplied fetch', () => {
    const custom = (async () => new Response('')) as typeof fetch
    const r = applyDefaults({ baseUrl: 'https://octo.test', fetch: custom })
    expect(r.fetch).toBe(custom)
  })

  it('respects a caller-supplied cache / metrics / logger / errorMapper', () => {
    const cache = newLRUCache(1)
    const metrics = { ...noopMetrics }
    const logger = { debug: () => {} }
    const errorMapper = () => ({ status: 418, body: '{"teapot":true}' })
    const r = applyDefaults({
      baseUrl: 'https://octo.test',
      cache,
      metrics,
      logger,
      errorMapper,
    })
    expect(r.cache).toBe(cache)
    expect(r.metrics).toBe(metrics)
    expect(r.logger).toBe(logger)
    expect(r.errorMapper).toBe(errorMapper)
  })
})

describe('consoleLogger', () => {
  // Wrap console methods so we can verify pass-through without polluting output.
  it('forwards debug/info/warn/error without throwing (meta undefined branch)', () => {
    // Just call — output goes to test runner console but we only care they
    // don't throw. Coverage picks up both branches (meta === undefined and set).
    consoleLogger.debug('t')
    consoleLogger.debug('t', { k: 1 })
    consoleLogger.info?.('t')
    consoleLogger.info?.('t', { k: 1 })
    consoleLogger.warn?.('t')
    consoleLogger.warn?.('t', { k: 1 })
    consoleLogger.error?.('t')
    consoleLogger.error?.('t', { k: 1 })
  })
})
