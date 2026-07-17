import { describe, expect, it } from 'vitest'

import { hashCacheKey, newLRUCache } from '../src/index.js'

describe('hashCacheKey', () => {
  it('returns 64 lowercase hex chars', () => {
    const h = hashCacheKey('anything')
    expect(h).toHaveLength(64)
    expect(/^[0-9a-f]+$/.test(h)).toBe(true)
  })

  it('is deterministic', () => {
    expect(hashCacheKey('same-input')).toBe(hashCacheKey('same-input'))
  })

  it('matches a known SHA-256 vector', () => {
    // sha256("") in hex.
    expect(hashCacheKey('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    )
  })
})

describe('newLRUCache', () => {
  it('rejects non-positive size', () => {
    expect(() => newLRUCache(0)).toThrow(/must be > 0/)
    expect(() => newLRUCache(-3)).toThrow(/must be > 0/)
  })

  it('get returns found=false for absent key', async () => {
    const c = newLRUCache(4)
    const g = await c.get('absent')
    expect(g).toEqual({ value: undefined, found: false })
  })

  it('set + get round-trips an object under a positive TTL', async () => {
    const c = newLRUCache(4)
    await c.set('k', { hello: 1 }, 1000)
    const g = await c.get('k')
    expect(g.found).toBe(true)
    expect(g.value).toEqual({ hello: 1 })
  })

  it('set with ttl<=0 stores without expiry (never-expire path)', async () => {
    const c = newLRUCache(4)
    await c.set('k', { forever: true }, 0)
    const g = await c.get('k')
    expect(g.found).toBe(true)
    expect(g.value).toEqual({ forever: true })
  })

  it('expires values after the TTL window', async () => {
    const c = newLRUCache(4)
    await c.set('k', { fresh: true }, 5)
    // Wait past the TTL.
    await new Promise((r) => setTimeout(r, 20))
    const g = await c.get('k')
    expect(g.found).toBe(false)
  })

  it('evicts the least recently used entry once max is exceeded', async () => {
    const c = newLRUCache(2)
    await c.set('a', { v: 1 }, 1000)
    await c.set('b', { v: 2 }, 1000)
    // Touch a so b becomes the LRU.
    await c.get('a')
    await c.set('c', { v: 3 }, 1000)
    const gb = await c.get('b')
    const ga = await c.get('a')
    const gc = await c.get('c')
    expect(gb.found).toBe(false)
    expect(ga.found).toBe(true)
    expect(gc.found).toBe(true)
  })

  it('delete removes a key and is idempotent for missing keys', async () => {
    const c = newLRUCache(4)
    await c.set('k', { hello: 1 }, 1000)
    await c.delete('k')
    const g = await c.get('k')
    expect(g.found).toBe(false)
    // Deleting again should not throw.
    await c.delete('k')
    await c.delete('never-existed')
  })

  it('wraps primitive values transparently through the object-constrained backend', async () => {
    // SDK-internal callers never store primitives, but the defensive wrap
    // path should still round-trip if someone stores a primitive.
    const c = newLRUCache(4)
    await c.set('num', 42 as unknown, 1000)
    const g = await c.get('num')
    expect(g.found).toBe(true)
    expect(g.value).toEqual({ __primitive: 42 })
  })
})
