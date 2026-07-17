import { afterEach, describe, expect, it } from 'vitest'

import {
  KindSession,
  OctoAuthError,
  newLRUCache,
  newSessionVerifier,
  type Principal,
} from '../src/index.js'
import { newRecordingLogger, newRecordingMetrics } from './helpers/recording.js'
import { startMockServer, type MockServerHandle } from './helpers/mock-server.js'

let handle: MockServerHandle | undefined

afterEach(async () => {
  if (handle) {
    await handle.close()
    handle = undefined
  }
})

describe('sessionVerifier — happy path', () => {
  it('resolves a valid token with include=context=false (ContextNotRequested)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'user-1',
        name: 'alice',
        role: 'writer',
        owned_bots: [{ uid: 'bot-1', name: 'Bot 1' }],
        // No context_included on purpose — but include=context off ignores it.
      }),
    }))
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const p = await v.verify('sess-token')
    expect(p.kind).toBe(KindSession)
    expect(p.uid).toBe('user-1')
    expect(p.name).toBe('alice')
    expect(p.role).toBe('writer')
    expect(p.relatedUids).toEqual(['user-1', 'bot-1'])
    expect(p.context.kind).toBe('not-requested')
    // Endpoint should NOT have ?include=context.
    expect(handle.requests[0]?.path).toBe('/v1/auth/verify')
    // Body should be JSON { token: ... }.
    expect(JSON.parse(handle.requests[0]!.body)).toEqual({ token: 'sess-token' })
  })

  it('deduplicates related uids preserving order', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'user-1',
        owned_bots: [
          { uid: 'bot-a', name: 'A' },
          { uid: '', name: 'empty' },
          { uid: 'bot-a', name: 'dup' },
          { uid: 'bot-b', name: 'B' },
          { uid: 'user-1', name: 'self' },
        ],
      }),
    }))
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const p = await v.verify('t')
    expect(p.relatedUids).toEqual(['user-1', 'bot-a', 'bot-b'])
  })
})

describe('sessionVerifier — include=context three-state', () => {
  it('appends ?include=context and yields ContextIncluded when the server returns true', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'u',
        context_included: true,
        spaces: ['s1', 's2'],
        owned_bots_by_space: { s1: ['b1'] },
      }),
    }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify('t')
    expect(handle.requests[0]?.path).toBe('/v1/auth/verify?include=context')
    expect(p.context.kind).toBe('included')
    expect(p.context.spaces).toEqual(['s1', 's2'])
    expect(p.context.ownedBotsBySpace).toEqual({ s1: ['b1'] })
  })

  it('yields ContextNotIncluded when the server returns false', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u', context_included: false }),
    }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify('t')
    expect(p.context.kind).toBe('not-included')
  })

  it('yields ContextUnknownServer for pre-v2 servers (field missing)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u' }), // no context_included
    }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify('t')
    expect(p.context.kind).toBe('unknown-server')
  })
})

describe('sessionVerifier — error status mapping', () => {
  it('401 → invalid-credential', async () => {
    handle = await startMockServer(async () => ({ status: 401, body: '{}' }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    try {
      await v.verify('t')
      expect.fail('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).kind).toBe('invalid-credential')
    }
  })

  it('403 → disabled', async () => {
    handle = await startMockServer(async () => ({ status: 403, body: '{}' }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'disabled' })
  })

  it('5xx → infra-failure', async () => {
    handle = await startMockServer(async () => ({ status: 502, body: '{}' }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('malformed JSON body → infra-failure (decode error)', async () => {
    handle = await startMockServer(async () => ({ status: 200, body: 'not-json' }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('missing uid on 200 → invalid-credential', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({}),
    }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('t')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('empty credential is rejected before any network call', async () => {
    handle = await startMockServer(async () => ({ status: 500, body: '{}' }))
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
    expect(handle.requests).toHaveLength(0)
  })
})

describe('sessionVerifier — network failures', () => {
  it('unreachable host → infra-failure', async () => {
    // Point at a port that nothing is listening on (very small chance of collision).
    const v = newSessionVerifier({ baseUrl: 'http://127.0.0.1:1', timeoutMs: 200 })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('client timeout → infra-failure', async () => {
    handle = await startMockServer(async () => {
      await new Promise((r) => setTimeout(r, 200))
      return { status: 200, body: JSON.stringify({ uid: 'u' }) }
    })
    const v = newSessionVerifier({ baseUrl: handle.baseUrl, timeoutMs: 30 })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('caller AbortSignal aborts the request', async () => {
    handle = await startMockServer(async () => {
      await new Promise((r) => setTimeout(r, 200))
      return { status: 200, body: JSON.stringify({ uid: 'u' }) }
    })
    const v = newSessionVerifier({ baseUrl: handle.baseUrl })
    const ac = new AbortController()
    setTimeout(() => ac.abort(), 30)
    await expect(v.verify('t', { signal: ac.signal })).rejects.toMatchObject({
      kind: 'infra-failure',
    })
  })
})

describe('sessionVerifier — cache behavior', () => {
  it('cache hit returns without a second network call', async () => {
    let hits = 0
    handle = await startMockServer(async () => {
      hits++
      return { status: 200, body: JSON.stringify({ uid: 'u' }) }
    })
    const cache = newLRUCache(10)
    const metrics = newRecordingMetrics()
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      cache,
      metrics,
      requestIncludeContext: false,
    })
    const first = await v.verify('sameToken')
    const second = await v.verify('sameToken')
    expect(hits).toBe(1)
    // Verify returns a defensive clone per call so callers can mutate freely
    // without racing with the cache.
    expect(second).not.toBe(first)
    expect(second).toEqual(first)
    expect(metrics.recorded.cacheHits.some((h) => h.hit)).toBe(true)
    expect(metrics.recorded.cacheHits.some((h) => !h.hit)).toBe(true)
  })

  it('caller mutation of the returned Principal does not poison the cache', async () => {
    let hits = 0
    handle = await startMockServer(async () => {
      hits++
      return {
        status: 200,
        body: JSON.stringify({
          uid: 'u-1',
          name: 'orig',
          role: 'member',
          owned_bots: [{ uid: 'b1', name: 'B1' }],
          context_included: true,
          spaces: ['s1'],
        }),
      }
    })
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: true,
    })
    const first = await v.verify('tok')
    // Poison every mutable field of the returned Principal.
    first.uid = 'attacker'
    first.name = 'attacker'
    first.role = 'root'
    first.spaceId = 's-attacker'
    if (first.relatedUids && first.relatedUids.length > 0) {
      ;(first.relatedUids as string[])[0] = 'attacker'
    }
    if (first.context.spaces && first.context.spaces.length > 0) {
      ;(first.context.spaces as string[])[0] = 's-attacker'
    }
    const second = await v.verify('tok')
    expect(hits).toBe(1)
    expect(second.uid).toBe('u-1')
    expect(second.name).toBe('orig')
    expect(second.role).toBe('member')
    expect(second.relatedUids?.[0]).toBe('u-1')
    expect(second.context.spaces?.[0]).toBe('s1')
  })

  it('negative cache: 401 is memoized then served on subsequent calls', async () => {
    let hits = 0
    handle = await startMockServer(async () => {
      hits++
      return { status: 401, body: '{}' }
    })
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    await expect(v.verify('badtoken')).rejects.toBeInstanceOf(OctoAuthError)
    await expect(v.verify('badtoken')).rejects.toBeInstanceOf(OctoAuthError)
    expect(hits).toBe(1)
  })

  it('infra failures are NOT cached', async () => {
    let hits = 0
    handle = await startMockServer(async () => {
      hits++
      return { status: 500, body: '{}' }
    })
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'infra-failure' })
    await expect(v.verify('t')).rejects.toMatchObject({ kind: 'infra-failure' })
    expect(hits).toBe(2)
  })

  it('hashCacheKey=false stores the raw token as the cache key', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u' }),
    }))
    const cache = newLRUCache(10)
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      cache,
      hashCacheKey: false,
      requestIncludeContext: false,
    })
    await v.verify('rawtoken')
    const g = await cache.get('s:rawtoken')
    expect(g.found).toBe(true)
    // And the hashed variant is absent.
    const g2 = await cache.get('s:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(g2.found).toBe(false)
  })

  it('cache returning an object missing context.kind falls through as a miss', async () => {
    let hits = 0
    handle = await startMockServer(async () => {
      hits++
      return { status: 200, body: JSON.stringify({ uid: 'u-fresh' }) }
    })
    // A malformed cache entry — matches the positive-key shape but omits
    // context.kind. The tightened isPrincipal guard must reject it so the
    // verifier falls through to a live fetch instead of returning a broken
    // Principal.
    const badPrincipal = { kind: 'session', uid: 'u-stale' } as unknown
    const backing = new Map<string, unknown>()
    const spyCache = {
      async get(key: string) {
        if (backing.has(key)) return { value: backing.get(key), found: true }
        return { value: undefined, found: false }
      },
      async set(key: string, value: unknown) {
        backing.set(key, value)
      },
      async delete(key: string) {
        backing.delete(key)
      },
    }
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      cache: spyCache,
      hashCacheKey: false,
      requestIncludeContext: false,
    })
    // Preload the bad shape under the exact positive cache key.
    backing.set('s:tok', badPrincipal)

    const p = await v.verify('tok')
    expect(hits).toBe(1)
    expect(p.uid).toBe('u-fresh')
    expect(p.context.kind).toBe('not-requested')
  })
})

describe('sessionVerifier — logging', () => {
  it('emits a debug log with a bounded body snippet on non-2xx', async () => {
    handle = await startMockServer(async () => ({
      status: 401,
      body: 'x'.repeat(500),
    }))
    const { logger, recorded } = newRecordingLogger()
    const v = newSessionVerifier({ baseUrl: handle.baseUrl, logger })
    await expect(v.verify('t')).rejects.toBeInstanceOf(OctoAuthError)
    const debug = recorded.messages.find(
      (m) => m.level === 'debug' && m.message.includes('verify response'),
    )
    expect(debug).toBeDefined()
    const snippet = debug!.meta?.['body_snippet'] as string
    // maxLoggedBodyBytes = 200.
    expect(snippet.length).toBeLessThanOrEqual(200)
  })
})

describe('sessionVerifier — Principal shape', () => {
  it('assigns empty strings for missing name/role (never undefined)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u' }),
    }))
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const p: Principal = await v.verify('t')
    expect(p.name).toBe('')
    expect(p.role).toBe('')
  })
})
