import { afterEach, describe, expect, it } from 'vitest'

import {
  BODY_FORBIDDEN,
  BODY_UNAUTHORIZED,
  KindBot,
  KindSession,
  newFullMultiVerifier,
  type Principal,
  type Verifier,
} from '../src/index.js'
import { expressMiddleware } from '../src/middleware/express.js'
import { startMockServer, type MockServerHandle } from './helpers/mock-server.js'

// Minimal mock req/res factories that satisfy the middleware's shape.
interface MockRes {
  statusCode: number
  headers: Record<string, string>
  body: string
  ended: boolean
  status(code: number): MockRes
  setHeader(name: string, value: string): void
  send(b: string): void
}

function mkRes(): MockRes {
  const res: MockRes = {
    statusCode: 0,
    headers: {},
    body: '',
    ended: false,
    status(code: number) {
      res.statusCode = code
      return res
    },
    setHeader(name, value) {
      res.headers[name] = value
    },
    send(b) {
      res.body = b
      res.ended = true
    },
  }
  return res
}

function mkReq(headers: Record<string, string | string[] | undefined>): {
  headers: Record<string, string | string[] | undefined>
  principal?: Principal
  credential?: { kind: 'session' | 'bot' | 'apikey'; raw: string }
} {
  return { headers }
}

let handle: MockServerHandle | undefined

afterEach(async () => {
  if (handle) {
    await handle.close()
    handle = undefined
  }
})

describe('expressMiddleware — construction', () => {
  it('throws synchronously when verifier is missing', () => {
    expect(() =>
      expressMiddleware({ verifier: undefined as unknown as Verifier }),
    ).toThrow(/verifier is required/)
  })

  it('returns a handler when configured', () => {
    const v = newFullMultiVerifier({ baseUrl: 'https://octo.test' })
    const mw = expressMiddleware({ verifier: v })
    expect(typeof mw).toBe('function')
  })
})

describe('expressMiddleware — happy path', () => {
  it('attaches req.principal and calls next() on success', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1' }),
    }))
    const v = newFullMultiVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const mw = expressMiddleware({ verifier: v })
    const req = mkReq({ authorization: 'Bearer sess-tok' })
    const res = mkRes()
    let nextCalled = false
    await mw(req, res, () => {
      nextCalled = true
    })
    expect(nextCalled).toBe(true)
    expect(req.principal?.uid).toBe('u1')
    expect(req.principal?.kind).toBe(KindSession)
    expect(req.credential?.raw).toBe('sess-tok')
    expect(res.ended).toBe(false)
  })
})

describe('expressMiddleware — RequireKind', () => {
  it('rejects mismatched kind with forbidden mapping', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1' }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, requireKind: KindBot })
    const req = mkReq({ authorization: 'Bearer sess-tok' })
    const res = mkRes()
    let nextCalled = false
    await mw(req, res, () => (nextCalled = true))
    expect(nextCalled).toBe(false)
    expect(res.statusCode).toBe(403)
    expect(res.body).toBe(BODY_FORBIDDEN)
    // No network call should have been issued.
    expect(handle.requests).toHaveLength(0)
  })
})

describe('expressMiddleware — error mapping', () => {
  it('extract failure → 401 unauthorized (byte-identical body)', async () => {
    handle = await startMockServer(async () => ({ status: 500, body: '{}' }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v })
    const req = mkReq({}) // no auth header
    const res = mkRes()
    await mw(req, res, () => {})
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(BODY_UNAUTHORIZED)
    expect(res.headers['Content-Type']).toBe('application/json')
  })

  it('server 401 → 401 unauthorized', async () => {
    handle = await startMockServer(async () => ({ status: 401, body: '{}' }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v })
    const req = mkReq({ authorization: 'Bearer sess-tok' })
    const res = mkRes()
    await mw(req, res, () => {})
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(BODY_UNAUTHORIZED)
  })

  it('custom errorMapper replaces the default', async () => {
    handle = await startMockServer(async () => ({ status: 401, body: '{}' }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({
      verifier: v,
      errorMapper: () => ({ status: 418, body: '{"teapot":true}' }),
    })
    const req = mkReq({ authorization: 'Bearer sess-tok' })
    const res = mkRes()
    await mw(req, res, () => {})
    expect(res.statusCode).toBe(418)
    expect(res.body).toBe('{"teapot":true}')
  })
})

describe('expressMiddleware — SpaceHeader enrichment', () => {
  it('v2 server (ContextIncluded): sid in spaces → SpaceID set', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'u1',
        context_included: true,
        spaces: ['s1', 's2'],
      }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })
    const req = mkReq({
      authorization: 'Bearer sess-tok',
      'x-space-id': 's1',
    })
    const res = mkRes()
    let nextCalled = false
    await mw(req, res, () => (nextCalled = true))
    expect(nextCalled).toBe(true)
    expect(req.principal?.spaceId).toBe('s1')
  })

  it('v2 server: sid NOT in spaces → 403 forbidden (fail-closed)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'u1',
        context_included: true,
        spaces: ['s1'],
      }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })
    const req = mkReq({
      authorization: 'Bearer sess-tok',
      'x-space-id': 'nope',
    })
    const res = mkRes()
    await mw(req, res, () => {})
    expect(res.statusCode).toBe(403)
    expect(res.body).toBe(BODY_FORBIDDEN)
  })

  it('pre-v2 (ContextUnknownServer): trusts the header', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      // No context_included → unknown-server.
      body: JSON.stringify({ uid: 'u1' }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })
    const req = mkReq({
      authorization: 'Bearer sess-tok',
      'x-space-id': 'trusted',
    })
    const res = mkRes()
    await mw(req, res, () => {})
    expect(req.principal?.spaceId).toBe('trusted')
  })

  it('ContextNotIncluded: trusts the header (v2 opt-out fallback)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1', context_included: false }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })
    const req = mkReq({
      authorization: 'Bearer sess-tok',
      'x-space-id': 'trusted',
    })
    const res = mkRes()
    await mw(req, res, () => {})
    expect(req.principal?.spaceId).toBe('trusted')
  })

  it('no spaceHeader configured → SpaceID stays untouched', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1' }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v })
    const req = mkReq({ authorization: 'Bearer sess-tok', 'x-space-id': 'x' })
    await mw(req, mkRes(), () => {})
    expect(req.principal?.spaceId).toBeUndefined()
  })

  it('spaceHeader set but header missing → SpaceID stays undefined', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1' }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })
    const req = mkReq({ authorization: 'Bearer sess-tok' })
    await mw(req, mkRes(), () => {})
    expect(req.principal?.spaceId).toBeUndefined()
  })

  it('bot realm ignores spaceHeader (already server-authoritative)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ bot_uid: 'b1', space_id: 'authoritative' }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })
    const req = mkReq({
      authorization: 'Bearer bf_bot',
      'x-space-id': 'ignored',
    })
    await mw(req, mkRes(), () => {})
    expect(req.principal?.spaceId).toBe('authoritative')
  })
})

describe('expressMiddleware — clone isolation (crucial for cache safety)', () => {
  it('mutation from enrichment does NOT leak into subsequent cache hits', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'u1',
        context_included: true,
        spaces: ['s1', 's2'],
      }),
    }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    const mw = expressMiddleware({ verifier: v, spaceHeader: 'X-Space-Id' })

    // First call sets spaceId=s1.
    const req1 = mkReq({ authorization: 'Bearer same-tok', 'x-space-id': 's1' })
    await mw(req1, mkRes(), () => {})
    expect(req1.principal?.spaceId).toBe('s1')

    // Second call (cache hit) with a DIFFERENT sid should get s2, not s1.
    const req2 = mkReq({ authorization: 'Bearer same-tok', 'x-space-id': 's2' })
    await mw(req2, mkRes(), () => {})
    expect(req2.principal?.spaceId).toBe('s2')
    // And request 1's principal is not affected.
    expect(req1.principal?.spaceId).toBe('s1')
    // The two principals are distinct instances.
    expect(req1.principal).not.toBe(req2.principal)
  })
})
