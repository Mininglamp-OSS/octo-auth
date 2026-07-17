/**
 * Cache interface + default LRU implementation.
 *
 * See design doc §6 and Go SDK's cache.go. Implementations must be safe for
 * concurrent use and MUST honor the per-entry ttlMs passed to Cache.set —
 * verifiers depend on TTL to bound the SSO revocation window.
 *
 * TS default backend: `lru-cache` v11 (matches Go's hashicorp/golang-lru
 * choice in "true LRU + per-entry TTL" semantics).
 */

import { createHash } from 'node:crypto'
import { LRUCache } from 'lru-cache'

/**
 * Cache backs verify-result memoization. All methods are async so future
 * Redis / distributed backends can drop in without an API change.
 */
export interface Cache {
  /**
   * Get returns { value, found: true } when present and not expired.
   * `found: false` covers both missing and expired entries.
   */
  get(key: string): Promise<{ value: unknown; found: boolean }>
  /** Store value under key with the given ttl (ms). A ttlMs <= 0 stores without expiry. */
  set(key: string, value: unknown, ttlMs: number): Promise<void>
  /** Delete key. It is not an error to delete a missing key. */
  delete(key: string): Promise<void>
}

/**
 * hashCacheKey returns the SHA-256 hex digest of raw. Verifiers call this
 * (when Config.hashCacheKey is true) so raw tokens never appear verbatim
 * inside cache keys.
 *
 * Returns 64 lowercase hex characters, deterministic.
 */
export function hashCacheKey(raw: string): string {
  return createHash('sha256').update(raw).digest('hex')
}

/**
 * newLRUCache builds a Cache bounded to maxSize entries. maxSize must be > 0.
 *
 * We use `lru-cache` v11's `ttl` option per-set (not the constructor default)
 * so different entries can carry different TTLs (session vs bot vs negative).
 * Setting `ttl: 0` on `set()` in lru-cache v11 means "no ttl", matching our
 * contract.
 */
export function newLRUCache(maxSize: number): Cache {
  if (maxSize <= 0) {
    throw new Error('octoauth: LRU cache size must be > 0')
  }
  const inner = new LRUCache<string, object>({
    max: maxSize,
    // Global fallback TTL — we always pass an explicit ttl on set().
    // Setting a non-zero value here would clobber per-entry TTLs.
  })
  return {
    async get(key: string) {
      const value = inner.get(key)
      if (value === undefined && !inner.has(key)) {
        return { value: undefined, found: false }
      }
      // has() true + value undefined would mean the caller stored undefined,
      // which the SDK does not do. Treat as miss defensively.
      if (value === undefined) {
        return { value: undefined, found: false }
      }
      return { value, found: true }
    },
    async set(key: string, value: unknown, ttlMs: number) {
      // SDK-internal callers always store objects (Principal or OctoAuthError);
      // wrap primitives defensively so lru-cache's object-constrained V type
      // stays happy.
      const stored: object =
        typeof value === 'object' && value !== null
          ? (value as object)
          : { __primitive: value }
      if (ttlMs > 0) {
        inner.set(key, stored, { ttl: ttlMs })
      } else {
        inner.set(key, stored)
      }
    },
    async delete(key: string) {
      inner.delete(key)
    },
  }
}
