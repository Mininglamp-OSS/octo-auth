import { afterEach, describe, expect, it } from 'vitest'

import {
  KindBot,
  OctoAuthError,
  newBotTokenVerifier,
} from '../src/index.js'
import { startMockServer, type MockServerHandle } from './helpers/mock-server.js'

let handle: MockServerHandle | undefined

afterEach(async () => {
  if (handle) {
    await handle.close()
    handle = undefined
  }
})

describe('botTokenVerifier — happy path', () => {
  it('resolves bf_ token and never sends include=context', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        bot_uid: 'bot-1',
        bot_name: 'summary-bot',
        role: 'writer',
        owner_uid: 'user-1',
        owner_name: 'alice',
        space_id: 'space-42',
      }),
    }))
    const v = newBotTokenVerifier({
      baseUrl: handle.baseUrl,
      // Even with include=context on, bot verifier must NOT append.
      requestIncludeContext: true,
    })
    const p = await v.verify('bf_botsecret')
    expect(p.kind).toBe(KindBot)
    expect(p.uid).toBe('bot-1')
    expect(p.name).toBe('summary-bot')
    expect(p.role).toBe('writer')
    expect(p.spaceId).toBe('space-42')
    expect(p.ownerUid).toBe('user-1')
    expect(p.ownerName).toBe('alice')
    expect(p.relatedUids).toEqual(['bot-1'])
    expect(p.context.kind).toBe('not-requested')
    expect(handle.requests[0]?.path).toBe('/v1/auth/verify-bot')
    expect(JSON.parse(handle.requests[0]!.body)).toEqual({
      bot_token: 'bf_botsecret',
    })
  })

  it('assigns empty strings for missing optional fields', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ bot_uid: 'bot-1', space_id: 's1' }),
    }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify('bf_x')
    expect(p.name).toBe('')
    expect(p.role).toBe('')
    expect(p.ownerUid).toBe('')
    expect(p.ownerName).toBe('')
  })
})

describe('botTokenVerifier — short-circuits', () => {
  it('empty credential rejected before any network call', async () => {
    handle = await startMockServer(async () => ({
      status: 500,
      body: '{}',
    }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
    expect(handle.requests).toHaveLength(0)
  })

  it('app_ prefix short-circuits WITHOUT any HTTP call (reserved realm)', async () => {
    handle = await startMockServer(async () => ({
      status: 500,
      body: '{}',
    }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    try {
      await v.verify('app_something')
      expect.fail('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).kind).toBe('invalid-credential')
      expect((err as OctoAuthError).verifier).toBe(KindBot)
      expect((err as Error).message).toMatch(/app_/)
    }
    expect(handle.requests).toHaveLength(0)
  })
})

describe('botTokenVerifier — response validation', () => {
  it('missing bot_uid → invalid-credential', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ space_id: 's1' }),
    }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('bf_x')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('missing space_id → invalid-credential (fleet middleware.go behavior)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ bot_uid: 'bot-1' }),
    }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('bf_x')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('401 → invalid-credential', async () => {
    handle = await startMockServer(async () => ({ status: 401, body: '{}' }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('bf_x')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('403 → disabled', async () => {
    handle = await startMockServer(async () => ({ status: 403, body: '{}' }))
    const v = newBotTokenVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('bf_x')).rejects.toMatchObject({ kind: 'disabled' })
  })
})
