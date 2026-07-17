import { afterEach, describe, expect, it } from 'vitest'

import { KindSession, OctoAuthError } from '../src/index.js'
import { AlgHS256, issueShortLivedToken } from '../src/layer2.js'
import { hocuspocusHook } from '../src/middleware/hocuspocus.js'
import { startMockServer, type MockServerHandle } from './helpers/mock-server.js'
import { newSessionVerifier } from '../src/index.js'

let handle: MockServerHandle | undefined
afterEach(async () => {
  if (handle) {
    await handle.close()
    handle = undefined
  }
})

describe('hocuspocusHook — construction', () => {
  it('requires either verifier or layer2', () => {
    expect(() => hocuspocusHook({})).toThrow(/verifier or options.layer2/)
  })

  it('rejects missing/empty token in payload', async () => {
    const hook = hocuspocusHook({
      layer2: {
        sigKey: new Uint8Array(32).fill(1),
        getPermissionEpoch: () => 0,
      },
    })
    await expect(
      hook.onAuthenticate({ token: '', documentName: 'doc' }),
    ).rejects.toBeInstanceOf(OctoAuthError)
  })
})

describe('hocuspocusHook — layer2 hot path', () => {
  const sigKey = new Uint8Array(32).fill(9)

  async function mkToken(permissionEpoch: number, uid = 'u1'): Promise<string> {
    return issueShortLivedToken({
      claims: { uid, documentName: 'doc-1', role: 'writer', permissionEpoch },
      sigKey,
      sigAlg: AlgHS256,
      ttlSeconds: 60,
    })
  }

  it('verifies JWT and returns user with role', async () => {
    const token = await mkToken(3)
    const hook = hocuspocusHook({
      layer2: { sigKey, getPermissionEpoch: async () => 3 },
    })
    const out = await hook.onAuthenticate({ token, documentName: 'doc-1' })
    expect(out.user.uid).toBe('u1')
    expect(out.user.role).toBe('writer')
  })

  it('rejects stale tokens (permissionEpoch < current)', async () => {
    const token = await mkToken(2)
    const hook = hocuspocusHook({
      layer2: { sigKey, getPermissionEpoch: () => 5 },
    })
    try {
      await hook.onAuthenticate({ token, documentName: 'doc-1' })
      expect.fail('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as Error).message).toMatch(/stale token/)
    }
  })

  it('propagates wrong-key rejection from verifyShortLivedToken', async () => {
    const token = await mkToken(3)
    const hook = hocuspocusHook({
      layer2: { sigKey: new Uint8Array(32).fill(0), getPermissionEpoch: () => 0 },
    })
    await expect(
      hook.onAuthenticate({ token, documentName: 'doc-1' }),
    ).rejects.toBeInstanceOf(OctoAuthError)
  })

  it('omits role from user when the layer2 claim role is empty', async () => {
    const token = await issueShortLivedToken({
      claims: { uid: 'u2', documentName: 'doc-1', role: '', permissionEpoch: 3 },
      sigKey,
      sigAlg: AlgHS256,
      ttlSeconds: 60,
    })
    const hook = hocuspocusHook({
      layer2: { sigKey, getPermissionEpoch: () => 3 },
    })
    const out = await hook.onAuthenticate({ token, documentName: 'doc-1' })
    expect(out.user.uid).toBe('u2')
    expect('role' in out.user).toBe(false)
  })

  it('rejects cross-document replay (token for doc-A opened on doc-B)', async () => {
    // Token minted for doc-A. Attacker replays it to open a connection
    // for doc-B. The doc binding MUST be enforced on the verify path.
    const token = await issueShortLivedToken({
      claims: { uid: 'u1', documentName: 'doc-A', role: 'writer', permissionEpoch: 3 },
      sigKey,
      sigAlg: AlgHS256,
      ttlSeconds: 60,
    })
    const hook = hocuspocusHook({
      layer2: { sigKey, getPermissionEpoch: () => 0 },
    })
    try {
      await hook.onAuthenticate({ token, documentName: 'doc-B' })
      expect.fail('should have rejected cross-document token')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).kind).toBe('forbidden')
      expect((err as Error).message).toMatch(/document_name/)
    }
  })

  it('rejects token with empty documentName claim (unbound token)', async () => {
    // Attacker crafts a token with empty document_name (bypasses the
    // per-document scope). Empty claim MUST be rejected — an unbound token
    // cannot back a document-scoped authorization decision.
    const token = await issueShortLivedToken({
      claims: { uid: 'u1', documentName: '', role: 'writer', permissionEpoch: 3 },
      sigKey,
      sigAlg: AlgHS256,
      ttlSeconds: 60,
    })
    const hook = hocuspocusHook({
      layer2: { sigKey, getPermissionEpoch: () => 0 },
    })
    try {
      await hook.onAuthenticate({ token, documentName: 'doc-1' })
      expect.fail('should have rejected empty documentName')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).kind).toBe('invalid-credential')
      expect((err as Error).message).toMatch(/missing document_name/)
    }
  })
})

describe('hocuspocusHook — verifier slow path', () => {
  it('falls through to verifier.verify and wraps role', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1', role: 'writer' }),
    }))
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const hook = hocuspocusHook({ verifier: v })
    const out = await hook.onAuthenticate({
      token: 'sess-tok',
      documentName: 'doc-1',
    })
    expect(out.user.uid).toBe('u1')
    expect(out.user.role).toBe('writer')
  })

  it('propagates 401 as an OctoAuthError', async () => {
    handle = await startMockServer(async () => ({ status: 401, body: '{}' }))
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const hook = hocuspocusHook({ verifier: v })
    await expect(
      hook.onAuthenticate({ token: 'sess-tok', documentName: 'doc' }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('sanity: verifier-mode principal.kind is session (unused here but tags the path)', async () => {
    handle = await startMockServer(async () => ({
      status: 200,
      body: JSON.stringify({ uid: 'u1' }),
    }))
    const v = newSessionVerifier({
      baseUrl: handle.baseUrl,
      requestIncludeContext: false,
    })
    const p = await v.verify('t')
    expect(p.kind).toBe(KindSession)
  })
})
