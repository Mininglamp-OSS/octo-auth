import { afterEach, describe, expect, it } from 'vitest'

import {
  KindAPIKey,
  OctoAuthError,
  newUserKeyVerifier,
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

describe('userKeyVerifier — short-circuits', () => {
  it('empty rejected before network', async () => {
    handle = await startMockServer(async () => ({ status: 500, body: '{}' }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
    expect(handle.requests).toHaveLength(0)
  })

  it('too-short uk_ rejected locally', async () => {
    handle = await startMockServer(async () => ({ status: 500, body: '{}' }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('uk_short')).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
    expect(handle.requests).toHaveLength(0)
  })

  it('missing uk_ prefix rejected locally', async () => {
    handle = await startMockServer(async () => ({ status: 500, body: '{}' }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify('a'.repeat(40))).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
    expect(handle.requests).toHaveLength(0)
  })
})

describe('userKeyVerifier — happy paths', () => {
  it('include=context on → ContextIncluded with sorted spaces from owned_bots map', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'user-1',
        space_id: 's1',
        context_included: true,
        // Deliberately out of order so we can prove sorting.
        owned_bots: { 's3': ['b3a'], 's1': ['b1a', 'b1b'], 's2': [] },
      }),
    }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify(goodKey)
    expect(p.kind).toBe(KindAPIKey)
    expect(p.uid).toBe('user-1')
    expect(p.spaceId).toBe('s1')
    expect(p.context.kind).toBe('included')
    expect(p.context.spaces).toEqual(['s1', 's2', 's3'])
    expect(p.context.ownedBotsBySpace).toEqual({
      s1: ['b1a', 'b1b'],
      s2: [],
      s3: ['b3a'],
    })
    expect(handle.requests[0]?.path).toBe('/v1/auth/verify-api-key?include=context')
    expect(JSON.parse(handle.requests[0]!.body)).toEqual({ api_key: goodKey })
  })

  it('include=context off → ContextNotRequested', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u', space_id: 's1' }),
    }))
    const v = newUserKeyVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const p = await v.verify(goodKey)
    expect(p.context.kind).toBe('not-requested')
    expect(handle.requests[0]?.path).toBe('/v1/auth/verify-api-key')
  })

  it('context_included=false → ContextNotIncluded', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({
        uid: 'u',
        space_id: 's1',
        context_included: false,
      }),
    }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify(goodKey)
    expect(p.context.kind).toBe('not-included')
  })

  it('pre-v2 server (context_included missing) → ContextUnknownServer', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u', space_id: 's1' }),
    }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    const p = await v.verify(goodKey)
    expect(p.context.kind).toBe('unknown-server')
  })
})

describe('userKeyVerifier — response validation & errors', () => {
  it('missing uid → invalid-credential', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ space_id: 's1' }),
    }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify(goodKey)).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('missing space_id → invalid-credential', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u' }),
    }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify(goodKey)).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('401 → invalid-credential', async () => {
    handle = await startMockServer(async () => ({ status: 401, body: '{}' }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify(goodKey)).rejects.toMatchObject({
      kind: 'invalid-credential',
    })
  })

  it('503 → infra-failure', async () => {
    handle = await startMockServer(async () => ({ status: 503, body: '{}' }))
    const v = newUserKeyVerifier({ baseUrl: handle.baseUrl })
    await expect(v.verify(goodKey)).rejects.toMatchObject({
      kind: 'infra-failure',
    })
  })
})
