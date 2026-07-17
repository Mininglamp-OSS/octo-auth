import { afterEach, describe, expect, it } from 'vitest'

import {
  DEFAULT_NOTIFY_TIMEOUT_MS,
  NotifyClient,
  maskToken,
  newNotifyClient,
} from '../src/internal-helpers/index.js'
import { startMockServer, type MockServerHandle } from './helpers/mock-server.js'
import { newRecordingLogger } from './helpers/recording.js'

let handle: MockServerHandle | undefined
afterEach(async () => {
  if (handle) {
    await handle.close()
    handle = undefined
  }
  // Clean up test env vars so tests are isolated.
  for (const k of Object.keys(process.env)) {
    if (k.startsWith('TEST_NOTIFY_')) delete process.env[k]
  }
})

describe('NotifyClient — construction fail-closed', () => {
  it('throws when baseUrl empty', () => {
    process.env['TEST_NOTIFY_A'] = 'test-secret-a'
    expect(
      () =>
        new NotifyClient({
          baseUrl: '',
          tokenEnvVar: 'TEST_NOTIFY_A',
        }),
    ).toThrow(/baseUrl is required/)
  })

  it('throws when tokenEnvVar empty', () => {
    expect(
      () =>
        new NotifyClient({
          baseUrl: 'https://octo.test',
          tokenEnvVar: '',
        }),
    ).toThrow(/tokenEnvVar is required/)
  })

  it('throws when env var missing (fail-closed at startup)', () => {
    delete process.env['TEST_NOTIFY_MISSING']
    expect(
      () =>
        new NotifyClient({
          baseUrl: 'https://octo.test',
          tokenEnvVar: 'TEST_NOTIFY_MISSING',
        }),
    ).toThrow(/fail-closed/)
  })

  it('exposes newNotifyClient factory equivalent to `new`', () => {
    process.env['TEST_NOTIFY_FACTORY'] = 'test-secret-factory'
    const c = newNotifyClient({
      baseUrl: 'https://octo.test',
      tokenEnvVar: 'TEST_NOTIFY_FACTORY',
    })
    expect(c).toBeInstanceOf(NotifyClient)
  })

  it('DEFAULT_NOTIFY_TIMEOUT_MS matches Go DefaultNotifyTimeout (10s)', () => {
    expect(DEFAULT_NOTIFY_TIMEOUT_MS).toBe(10_000)
  })
})

describe('NotifyClient — send', () => {
  it('POSTs JSON with X-Internal-Token header and honors 2xx', async () => {
    handle = await startMockServer(async () => ({ status: 204 }))
    process.env['TEST_NOTIFY_SEND'] = 'test-secret-send-token'
    const c = new NotifyClient({
      baseUrl: handle.baseUrl,
      tokenEnvVar: 'TEST_NOTIFY_SEND',
    })
    await c.send({ channelId: 'ch-1', message: 'hi' })
    const req = handle.requests[0]!
    expect(req.method).toBe('POST')
    expect(req.path).toBe('/v1/internal/notify')
    expect(req.headers['x-internal-token']).toBe('test-secret-send-token')
    expect(JSON.parse(req.body)).toEqual({ channel_id: 'ch-1', message: 'hi' })
  })

  it('non-2xx surfaces status code but NOT server body (anti-enumeration)', async () => {
    handle = await startMockServer(async () => ({
      status: 500,
      body: '{"secret_internal_reason":"user X does not exist in space Y"}',
    }))
    process.env['TEST_NOTIFY_ERR'] = 'test-secret-err-token'
    const c = new NotifyClient({
      baseUrl: handle.baseUrl,
      tokenEnvVar: 'TEST_NOTIFY_ERR',
    })
    try {
      await c.send({ channelId: 'x', message: 'y' })
      expect.fail('should have thrown')
    } catch (err) {
      const msg = (err as Error).message
      expect(msg).toMatch(/status 500/)
      // No leak of the server body:
      expect(msg).not.toMatch(/secret_internal_reason/)
      expect(msg).not.toMatch(/user X/)
    }
  })

  it('rawBody overrides the primary shape', async () => {
    handle = await startMockServer(async () => ({ status: 200 }))
    process.env['TEST_NOTIFY_RAW'] = 'test-secret-raw-token'
    const c = new NotifyClient({
      baseUrl: handle.baseUrl,
      tokenEnvVar: 'TEST_NOTIFY_RAW',
    })
    await c.send({
      channelId: 'ignored',
      message: 'ignored',
      rawBody: '{"custom_shape":true,"foo":42}',
    })
    expect(JSON.parse(handle.requests[0]!.body)).toEqual({
      custom_shape: true,
      foo: 42,
    })
  })

  it('transport failure surfaces without server body context', async () => {
    process.env['TEST_NOTIFY_NET'] = 'test-secret-net-token'
    const c = new NotifyClient({
      baseUrl: 'http://127.0.0.1:1', // deliberately unreachable
      tokenEnvVar: 'TEST_NOTIFY_NET',
      timeoutMs: 200,
    })
    await expect(
      c.send({ channelId: 'x', message: 'y' }),
    ).rejects.toThrow(/notify request failed/)
  })

  it('logger only records maskToken hint, never the raw secret', async () => {
    handle = await startMockServer(async () => ({ status: 204 }))
    process.env['TEST_NOTIFY_LOG'] = 'test-secret-super-long-token-value-1234'
    const { logger, recorded } = newRecordingLogger()
    const c = new NotifyClient({
      baseUrl: handle.baseUrl,
      tokenEnvVar: 'TEST_NOTIFY_LOG',
      logger,
    })
    await c.send({ channelId: 'c', message: 'm' })
    for (const m of recorded.messages) {
      // The raw token must never appear in log lines.
      expect(m.message + JSON.stringify(m.meta ?? {})).not.toMatch(
        /test-secret-super-long-token-value-1234/,
      )
    }
    // But we should see the masked hint (sha256:xxxxxx fingerprint of the token).
    const flat = JSON.stringify(recorded)
    expect(flat).toMatch(/sha256:[0-9a-f]{6}/)
    expect(flat).toContain(maskToken('test-secret-super-long-token-value-1234'))
  })
})

describe('maskToken', () => {
  it('returns empty string for empty input', () => {
    expect(maskToken('')).toBe('')
  })

  it('returns sha256:<6hex> fingerprint for non-empty input', () => {
    expect(maskToken('short')).toMatch(/^sha256:[0-9a-f]{6}$/)
    expect(maskToken('abcdefghijklm')).toMatch(/^sha256:[0-9a-f]{6}$/)
  })

  it('is stable for the same input (correlation-friendly)', () => {
    expect(maskToken('abc')).toBe(maskToken('abc'))
  })

  it('differs for different inputs', () => {
    expect(maskToken('abc')).not.toBe(maskToken('abd'))
  })

  it('leaks no prefix of the raw secret', () => {
    const raw = 'XYZ-live-Kj8mNqPwRt7VaBcDeF'
    const masked = maskToken(raw)
    expect(masked).not.toContain(raw)
    expect(masked).not.toContain(raw.slice(0, 8))
    expect(masked).not.toContain(raw.slice(0, 4))
  })
})

// Reviewer P1-E: X-Internal-Token MUST NOT be replayed to a Location on
// 3xx. WHATWG fetch strips Authorization on cross-origin redirects but
// NOT arbitrary custom headers, so we rely on `redirect: 'error'` to
// halt at the redirect and throw. The attacker mock server counts the
// number of times it received a request (must stay at 0).
describe('NotifyClient — redirect defense (P1-E)', () => {
  it('307 redirect → error, attacker receives 0 requests', async () => {
    process.env['TEST_NOTIFY_R1'] = 'shared-secret-value'
    let attackerHits = 0
    const attacker = await startMockServer(async () => {
      attackerHits++
      return { status: 200, body: '{}' }
    })
    try {
      handle = await startMockServer(async () => ({
        status: 307,
        headers: { Location: `${attacker.baseUrl}/steal` },
      }))
      const c = newNotifyClient({
        baseUrl: handle.baseUrl,
        tokenEnvVar: 'TEST_NOTIFY_R1',
      })
      await expect(c.send({ channelId: 'c', message: 'm' })).rejects.toThrow(
        /notify request failed/,
      )
      expect(attackerHits).toBe(0)
    } finally {
      await attacker.close()
    }
  })

  it('308 redirect → error, attacker receives 0 requests', async () => {
    process.env['TEST_NOTIFY_R2'] = 'another-shared-secret'
    let attackerHits = 0
    const attacker = await startMockServer(async () => {
      attackerHits++
      return { status: 200, body: '{}' }
    })
    try {
      handle = await startMockServer(async () => ({
        status: 308,
        headers: { Location: `${attacker.baseUrl}/steal` },
      }))
      const c = newNotifyClient({
        baseUrl: handle.baseUrl,
        tokenEnvVar: 'TEST_NOTIFY_R2',
      })
      await expect(c.send({ channelId: 'c', message: 'm' })).rejects.toThrow(
        /notify request failed/,
      )
      expect(attackerHits).toBe(0)
    } finally {
      await attacker.close()
    }
  })
})

// Reviewer P1-G: notify responses are effectively empty (status-only
// contract); a compromised upstream that streams a huge body MUST NOT
// OOM the SDK consumer. Send returns success (2xx) but the drain is
// capped by MAX_NOTIFY_BODY_BYTES.
describe('NotifyClient — body drain bounded (P1-G)', () => {
  it('oversized 200 body does not OOM; send returns success', async () => {
    process.env['TEST_NOTIFY_BIG'] = 'tok'
    // 1 MiB body — 16x the 64 KiB drain cap.
    const oversized = 'A'.repeat(1 << 20)
    handle = await startMockServer(async () => ({
      status: 200,
      body: oversized,
    }))
    const c = newNotifyClient({
      baseUrl: handle.baseUrl,
      tokenEnvVar: 'TEST_NOTIFY_BIG',
    })
    await expect(
      c.send({ channelId: 'c', message: 'm' }),
    ).resolves.toBeUndefined()
  })
})
