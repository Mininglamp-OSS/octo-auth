import { describe, expect, it } from 'vitest'
import type { BotResolver, ResolvedPrincipal, ResolveRequest } from '../src/index.js'
import { expressBotResolveMiddleware, type MinimalExpressRequest } from '../src/middleware/express.js'

function response() {
  return {
    statusCode: 0, body: '',
    status(code: number) { this.statusCode = code; return this },
    setHeader(_name: string, _value: string) {},
    send(body: string) { this.body = body },
  }
}

describe('expressBotResolveMiddleware', () => {
  it('uses the route-fixed Action instead of a caller Action', async () => {
    let received: ResolveRequest | undefined
    const resolver: BotResolver = {
      async resolve(_credential, request) {
        received = request
        return { mode: 'OBO',
          actor: { uid: 'bot-1', kind: 'BOT', spaceId: 'S' },
          subject: { uid: 'owner-1', kind: 'HUMAN', spaceId: 'S' },
          delegation: { grantId: 7, matchedScope: 'ALL', policyVersion: 1,
            action: 'project.read', decisionId: 'D' } }
      },
    }
    const req: MinimalExpressRequest = { headers: { authorization: 'Bearer bf_secret' },
      query: { obo: 'true', space_id: 'S', action: 'admin.write' } }
    const res = response()
    let nextCalled = false
    await expressBotResolveMiddleware({ resolver, mode: 'OBO', action: 'project.read' })(req, res, () => { nextCalled = true })
    expect(nextCalled).toBe(true)
    expect(received).toEqual({ mode: 'OBO', spaceId: 'S', action: 'project.read' })
    expect((req.resolvedPrincipal as ResolvedPrincipal).subject.uid).toBe('owner-1')
  })

  it('refuses a missing OBO marker without falling back', async () => {
    let called = false
    const resolver: BotResolver = { async resolve() { called = true; throw new Error('unexpected') } }
    const req: MinimalExpressRequest = { headers: { authorization: 'Bearer bf_secret' }, query: { space_id: 'S' } }
    const res = response()
    await expressBotResolveMiddleware({ resolver, mode: 'OBO', action: 'project.read' })(req, res, () => {})
    expect(res.statusCode).toBe(400)
    expect(called).toBe(false)
  })
})
