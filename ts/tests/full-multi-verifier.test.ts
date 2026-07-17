import { afterEach, describe, expect, it } from 'vitest'

import {
  KindAPIKey,
  KindBot,
  KindSession,
  OctoAuthError,
  newFullMultiVerifier,
} from '../src/index.js'
import { startMockServer, type MockServerHandle } from './helpers/mock-server.js'

let handle: MockServerHandle | undefined

afterEach(async () => {
  if (handle) {
    await handle.close()
    handle = undefined
  }
})

const goodKey = 'uk_' + 'a'.repeat(32)

describe('newFullMultiVerifier — end-to-end dispatch', () => {
  it('dispatches by prefix to the three verifiers', async () => {
    handle = await startMockServer(async (req) => {
      switch (req.path.split('?')[0]) {
        case '/v1/auth/verify':
          return {
            status: 200,
            body: JSON.stringify({ uid: 'user-1', name: 'a', role: 'r' }),
          }
        case '/v1/auth/verify-bot':
          return {
            status: 200,
            body: JSON.stringify({ bot_uid: 'bot-1', space_id: 's1' }),
          }
        case '/v1/auth/verify-api-key':
          return {
            status: 200,
            body: JSON.stringify({ uid: 'user-1', space_id: 's1' }),
          }
        default:
          return { status: 404, body: '{}' }
      }
    })
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })

    const session = await v.verify('plain-session')
    expect(session.kind).toBe(KindSession)
    expect(session.uid).toBe('user-1')

    const bot = await v.verify('bf_botsecret')
    expect(bot.kind).toBe(KindBot)
    expect(bot.uid).toBe('bot-1')

    const key = await v.verify(goodKey)
    expect(key.kind).toBe(KindAPIKey)
    expect(key.uid).toBe('user-1')
  })

  it('shares a single cache across children (same cfg instance)', async () => {
    let sessionCalls = 0
    handle = await startMockServer(async (req) => {
      if (req.path.startsWith('/v1/auth/verify')) {
        sessionCalls++
        return {
          status: 200,
          body: JSON.stringify({ uid: 'u', context_included: false }),
        }
      }
      return { status: 404, body: '{}' }
    })
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    await v.verify('same-session-tok')
    await v.verify('same-session-tok')
    expect(sessionCalls).toBe(1)
  })

  it('app_ short-circuits end-to-end without a network call', async () => {
    handle = await startMockServer(async () => ({ status: 500, body: '{}' }))
    const v = newFullMultiVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('app_something')).rejects.toBeInstanceOf(
      OctoAuthError,
    )
    expect(handle.requests).toHaveLength(0)
  })
})
