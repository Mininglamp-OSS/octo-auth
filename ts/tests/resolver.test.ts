import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { newBotResolver, OctoAuthError } from '../src/index.js'

const fixtures = JSON.parse(readFileSync(new URL('../../contract/resolve-fixtures.json', import.meta.url), 'utf8')) as {
  obo: Record<string, unknown>
  as_bot: Record<string, unknown>
  delegation_denied: Record<string, unknown>
}

describe('Bot Resolver', () => {
  it('uses the Bot credential without a service token', () => {
    expect(() => newBotResolver({ baseUrl: 'http://resolve.test' })).not.toThrow()
  })

  it('sends an explicit Space and controlled Action, then returns both identities', async () => {
    const calls: { url: string; init: RequestInit }[] = []
    const resolver = newBotResolver({
      baseUrl: 'http://resolve.test',
      fetch: async (url, init) => {
        calls.push({ url: String(url), init: init ?? {} })
        return new Response(JSON.stringify(fixtures.obo), { status: 200 })
      },
    })
    const p = await resolver.resolve('bf_secret', { mode: 'OBO', spaceId: 'space-1', action: 'project.read' })
    expect(p.actor.uid).toBe('bot-1')
    expect(p.subject.uid).toBe('owner-1')
    expect(p.delegation?.matchedScope).toBe('ALL')
    expect(calls[0]?.url).toBe('http://resolve.test/v1/internal/auth/resolve')
    expect(Object.fromEntries(new Headers(calls[0]?.init.headers))).toEqual({
      accept: 'application/json',
      'cache-control': 'no-store',
      'content-type': 'application/json',
    })
    expect(JSON.parse(String(calls[0]?.init.body))).toEqual({
      bot_token: 'bf_secret', mode: 'OBO', space_id: 'space-1', action: 'project.read',
    })
  })

  it('rejects a missing Space before network access', async () => {
    let called = false
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => { called = true; return new Response('{}') } })
    await expect(resolver.resolve('bf_secret', { mode: 'AS_BOT', spaceId: '' }))
      .rejects.toMatchObject({ kind: 'invalid-request' })
    expect(called).toBe(false)
  })

  it.each([
    'session-token',
    'uk_01234567890123456789012345678901',
    'app_reserved',
    'bf_',
  ])('rejects non-user-Bot credential %s before network access', async (credential) => {
    let called = false
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => { called = true; return new Response('{}') } })
    await expect(resolver.resolve(credential, { mode: 'AS_BOT', spaceId: 'S' }))
      .rejects.toMatchObject({ kind: 'invalid-credential' })
    expect(called).toBe(false)
  })

  it('maps delegation_denied by status and code, not by status alone', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => new Response(JSON.stringify(fixtures.delegation_denied), { status: 403 }) })
    try {
      await resolver.resolve('bf_secret', { mode: 'OBO', spaceId: 'space-1', action: 'project.read' })
      expect.fail('expected denial')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect(err).toMatchObject({ kind: 'forbidden', code: 'delegation_denied', requestId: 'request-1' })
    }
  })

  it('returns the same Actor and Subject for AS_BOT without an Action', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async (_url, init) => {
        expect(JSON.parse(String(init?.body))).toEqual({ bot_token: 'bf_secret', mode: 'AS_BOT', space_id: 'space-1' })
        return new Response(JSON.stringify(fixtures.as_bot), { status: 200 })
      },
    })
    const p = await resolver.resolve('bf_secret', { mode: 'AS_BOT', spaceId: 'space-1' })
    expect(p.actor).toEqual(p.subject)
    expect(p.delegation).toBeUndefined()
  })

  it('normalizes an empty AS_BOT action to an omitted wire field', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async (_url, init) => {
        expect(JSON.parse(String(init?.body))).toEqual({ bot_token: 'bf_secret', mode: 'AS_BOT', space_id: 'space-1' })
        return new Response(JSON.stringify(fixtures.as_bot), { status: 200 })
      },
    })
    await expect(resolver.resolve('bf_secret', { mode: 'AS_BOT', spaceId: 'space-1', action: '' }))
      .resolves.toMatchObject({ mode: 'AS_BOT' })
  })

  it('rejects the removed service error code', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => new Response('{"code":"untrusted_service","request_id":"R"}', { status: 401 }) })
    await expect(resolver.resolve('bf_secret', { mode: 'AS_BOT', spaceId: 'S' }))
      .rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('rejects a successful response that chooses the wrong Subject kind', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => new Response(JSON.stringify({ mode: 'OBO',
        actor: { uid: 'bot-1', kind: 'BOT', space_id: 'S' },
        subject: { uid: 'bot-2', kind: 'BOT', space_id: 'S' } }), { status: 200 }) })
    await expect(resolver.resolve('bf_secret', { mode: 'OBO', spaceId: 'S', action: 'project.read' }))
      .rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it.each([
    ['missing policy version', { policy_version: undefined }],
    ['zero policy version', { policy_version: 0 }],
    ['negative policy version', { policy_version: -1 }],
    ['missing decision id', { decision_id: undefined }],
    ['invalid decision id', { decision_id: 'not-a-decision-id' }],
    ['zero grant id', { grant_id: 0 }],
    ['wrong scope', { matched_scope: 'PROJECT' }],
    ['wrong action', { action: 'admin.write' }],
  ])('rejects an OBO response with %s', async (_name, replacement) => {
    const wire = structuredClone(fixtures.obo)
    const delegation = wire.delegation as Record<string, unknown>
    Object.assign(delegation, replacement)
    for (const [key, value] of Object.entries(replacement)) {
      if (value === undefined) delete delegation[key]
    }
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => new Response(JSON.stringify(wire), { status: 200 }) })
    await expect(resolver.resolve('bf_secret', { mode: 'OBO', spaceId: 'space-1', action: 'project.read' }))
      .rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('rejects an error response without request_id', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => new Response('{"code":"delegation_denied"}', { status: 403 }) })
    await expect(resolver.resolve('bf_secret', { mode: 'OBO', spaceId: 'S', action: 'project.read' }))
      .rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('rejects an oversized response body', async () => {
    const resolver = newBotResolver({ baseUrl: 'http://resolve.test',
      fetch: async () => new Response('x'.repeat((1 << 20) + 1), { status: 200 }) })
    await expect(resolver.resolve('bf_secret', { mode: 'AS_BOT', spaceId: 'S' }))
      .rejects.toMatchObject({ kind: 'infra-failure' })
  })
})
