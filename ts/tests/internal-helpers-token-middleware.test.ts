import { afterEach, describe, expect, it } from 'vitest'

import {
  INTERNAL_TOKEN_UNAUTHORIZED_BODY,
  expressInternalTokenMiddleware,
  wrapNodeInternalTokenMiddleware,
  type NodeHandler,
} from '../src/internal-helpers/index.js'

// Simple mock res factory similar to middleware-express.test.ts.
interface MockRes {
  statusCode: number
  headers: Record<string, string>
  body: string
  ended: boolean
  status(code: number): MockRes
  setHeader(name: string, value: string): void
  send(b: string): void
  end(): void
}

function mkRes(): MockRes {
  const r: MockRes = {
    statusCode: 0,
    headers: {},
    body: '',
    ended: false,
    status(code) {
      r.statusCode = code
      return r
    },
    setHeader(name, value) {
      r.headers[name] = value
    },
    send(b) {
      r.body = b
      r.ended = true
    },
    end() {
      r.ended = true
    },
  }
  return r
}

interface MockNodeRes {
  statusCode: number
  headers: Record<string, string>
  body: string
  writeHead(status: number, headers?: Record<string, string>): void
  end(chunk?: string): void
}
function mkNodeRes(): MockNodeRes {
  const r: MockNodeRes = {
    statusCode: 0,
    headers: {},
    body: '',
    writeHead(status, headers) {
      r.statusCode = status
      if (headers) Object.assign(r.headers, headers)
    },
    end(chunk) {
      if (chunk !== undefined) r.body = chunk
    },
  }
  return r
}

afterEach(() => {
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('TEST_INT_TOKEN_')) delete process.env[k]
  }
})

describe('expressInternalTokenMiddleware — construction', () => {
  it('throws when headerName missing', () => {
    process.env['TEST_INT_TOKEN_A'] = 'test-secret-a'
    expect(() =>
      expressInternalTokenMiddleware({
        headerName: '',
        tokenEnvVar: 'TEST_INT_TOKEN_A',
      }),
    ).toThrow(/headerName is required/)
  })

  it('throws when tokenEnvVar missing', () => {
    expect(() =>
      expressInternalTokenMiddleware({
        headerName: 'X-Test',
        tokenEnvVar: '',
      }),
    ).toThrow(/tokenEnvVar is required/)
  })

  it('throws (fail-closed) when env var empty', () => {
    delete process.env['TEST_INT_TOKEN_MISS']
    expect(() =>
      expressInternalTokenMiddleware({
        headerName: 'X-Test',
        tokenEnvVar: 'TEST_INT_TOKEN_MISS',
      }),
    ).toThrow(/fail-closed/)
  })

  it('returns a handler when configured', () => {
    process.env['TEST_INT_TOKEN_OK'] = 'test-secret-ok'
    const mw = expressInternalTokenMiddleware({
      headerName: 'X-Test',
      tokenEnvVar: 'TEST_INT_TOKEN_OK',
    })
    expect(typeof mw).toBe('function')
  })
})

describe('expressInternalTokenMiddleware — AntiEnumeration', () => {
  const SECRET = 'test-secret-anti-enum-token'

  function buildMW() {
    process.env['TEST_INT_TOKEN_AE'] = SECRET
    return expressInternalTokenMiddleware({
      headerName: 'X-Runtime-Admin-Token',
      tokenEnvVar: 'TEST_INT_TOKEN_AE',
    })
  }

  it('missing header → 401 with byte-identical body', () => {
    const mw = buildMW()
    const req = { headers: {} }
    const res = mkRes()
    let nextCalled = false
    mw(req, res, () => (nextCalled = true))
    expect(nextCalled).toBe(false)
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
    expect(res.body).toBe('{"error":"unauthorized"}')
    expect(res.headers['Content-Type']).toBe('application/json')
  })

  it('empty header → 401 with byte-identical body', () => {
    const mw = buildMW()
    const req = { headers: { 'x-runtime-admin-token': '' } }
    const res = mkRes()
    mw(req, res, () => {})
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
  })

  it('short-wrong header → 401 with byte-identical body', () => {
    const mw = buildMW()
    const req = { headers: { 'x-runtime-admin-token': 'x' } }
    const res = mkRes()
    mw(req, res, () => {})
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
  })

  it('same-length-wrong header → 401 with byte-identical body', () => {
    const mw = buildMW()
    // Same length as SECRET but different content.
    const wrong = 'z'.repeat(SECRET.length)
    const req = { headers: { 'x-runtime-admin-token': wrong } }
    const res = mkRes()
    mw(req, res, () => {})
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
  })
})

describe('expressInternalTokenMiddleware — accept', () => {
  it('calls next() and does NOT touch res when token matches', () => {
    process.env['TEST_INT_TOKEN_ACC'] = 'test-secret-accept'
    const mw = expressInternalTokenMiddleware({
      headerName: 'X-Admin',
      tokenEnvVar: 'TEST_INT_TOKEN_ACC',
    })
    const req = { headers: { 'x-admin': 'test-secret-accept' } }
    const res = mkRes()
    let nextCalled = false
    mw(req, res, () => (nextCalled = true))
    expect(nextCalled).toBe(true)
    expect(res.ended).toBe(false)
    expect(res.statusCode).toBe(0)
  })

  it('case-insensitive header lookup (Express usually lowercases already)', () => {
    process.env['TEST_INT_TOKEN_CASE'] = 'test-secret-case'
    const mw = expressInternalTokenMiddleware({
      headerName: 'X-Admin',
      tokenEnvVar: 'TEST_INT_TOKEN_CASE',
    })
    const req = { headers: { 'X-Admin': 'test-secret-case' } }
    const res = mkRes()
    let nextCalled = false
    mw(req, res, () => (nextCalled = true))
    expect(nextCalled).toBe(true)
  })

  it('coerces array header values to the first element', () => {
    process.env['TEST_INT_TOKEN_ARR'] = 'test-secret-array'
    const mw = expressInternalTokenMiddleware({
      headerName: 'X-Admin',
      tokenEnvVar: 'TEST_INT_TOKEN_ARR',
    })
    const req = {
      headers: { 'x-admin': ['test-secret-array', 'test-secret-other'] },
    }
    const res = mkRes()
    let nextCalled = false
    mw(req, res, () => (nextCalled = true))
    expect(nextCalled).toBe(true)
  })
})

describe('wrapNodeInternalTokenMiddleware', () => {
  it('rejects unauthorized request with 401 + byte-identical body', () => {
    process.env['TEST_INT_TOKEN_N1'] = 'test-secret-node-1'
    const wrapped = wrapNodeInternalTokenMiddleware(
      { headerName: 'X-Admin', tokenEnvVar: 'TEST_INT_TOKEN_N1' },
      () => {
        throw new Error('next should not be called')
      },
    )
    const req = { headers: {} }
    const res = mkNodeRes()
    wrapped(req, res)
    expect(res.statusCode).toBe(401)
    expect(res.body).toBe(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
    expect(res.headers['Content-Type']).toBe('application/json')
  })

  it('calls next when token matches', () => {
    process.env['TEST_INT_TOKEN_N2'] = 'test-secret-node-2'
    let nextCalled = false
    const wrapped = wrapNodeInternalTokenMiddleware(
      { headerName: 'X-Admin', tokenEnvVar: 'TEST_INT_TOKEN_N2' },
      () => {
        nextCalled = true
      },
    )
    const req = { headers: { 'x-admin': 'test-secret-node-2' } }
    const res = mkNodeRes()
    wrapped(req, res)
    expect(nextCalled).toBe(true)
    expect(res.statusCode).toBe(0)
  })

  it('throws when next is not a function', () => {
    process.env['TEST_INT_TOKEN_N3'] = 'test-secret-node-3'
    expect(() =>
      wrapNodeInternalTokenMiddleware(
        { headerName: 'X-Admin', tokenEnvVar: 'TEST_INT_TOKEN_N3' },
        undefined as unknown as NodeHandler,
      ),
    ).toThrow(/next handler is required/)
  })
})
