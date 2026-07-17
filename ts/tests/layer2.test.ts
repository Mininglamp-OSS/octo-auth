import { describe, expect, it } from 'vitest'
import { SignJWT } from 'jose'

import { OctoAuthError } from '../src/index.js'
import {
  AlgEdDSA,
  AlgHS256,
  DEFAULT_TTL_SECONDS,
  MIN_HS256_KEY_SIZE,
  issueShortLivedToken,
  verifyShortLivedToken,
} from '../src/layer2.js'

const goodKey = new Uint8Array(32).fill(9)

describe('layer2 — HS256 round-trip', () => {
  it('issues and verifies a valid token', async () => {
    const token = await issueShortLivedToken({
      claims: {
        uid: 'u1',
        documentName: 'doc-1',
        role: 'writer',
        permissionEpoch: 3,
      },
      sigKey: goodKey,
      sigAlg: AlgHS256,
      ttlSeconds: 60,
    })
    const claims = await verifyShortLivedToken(token, {
      sigKey: goodKey,
      sigAlg: AlgHS256,
    })
    expect(claims.uid).toBe('u1')
    expect(claims.documentName).toBe('doc-1')
    expect(claims.role).toBe('writer')
    expect(claims.permissionEpoch).toBe(3)
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  it('default TTL applies when ttlSeconds unset', async () => {
    expect(DEFAULT_TTL_SECONDS).toBe(300)
    const before = Math.floor(Date.now() / 1000)
    const token = await issueShortLivedToken({
      claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
      sigKey: goodKey,
      sigAlg: AlgHS256,
    })
    const c = await verifyShortLivedToken(token, {
      sigKey: goodKey,
      sigAlg: AlgHS256,
    })
    // exp should be roughly before + DEFAULT_TTL_SECONDS (±2s for clock).
    expect(c.exp).toBeGreaterThanOrEqual(before + DEFAULT_TTL_SECONDS - 2)
    expect(c.exp).toBeLessThanOrEqual(before + DEFAULT_TTL_SECONDS + 2)
  })
})

describe('layer2 — issue validation', () => {
  it('rejects missing uid', async () => {
    await expect(
      issueShortLivedToken({
        claims: { uid: '', documentName: '', role: '', permissionEpoch: 0 },
        sigKey: goodKey,
        sigAlg: AlgHS256,
      }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects empty sigKey', async () => {
    await expect(
      issueShortLivedToken({
        claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
        sigKey: new Uint8Array(0),
        sigAlg: AlgHS256,
      }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects short HS256 sigKey (< 32 bytes)', async () => {
    await expect(
      issueShortLivedToken({
        claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
        sigKey: new Uint8Array(MIN_HS256_KEY_SIZE - 1),
        sigAlg: AlgHS256,
      }),
    ).rejects.toThrow(/HS256 secret must be at least/)
  })

  it('rejects EdDSA (v1 gap → unsupported-algorithm)', async () => {
    try {
      await issueShortLivedToken({
        claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
        sigKey: goodKey,
        sigAlg: AlgEdDSA,
      })
      expect.fail('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).kind).toBe('infra-failure')
      expect((err as Error).message).toMatch(/unsupported signature algorithm/)
    }
  })

  it('rejects unknown algorithm', async () => {
    await expect(
      issueShortLivedToken({
        claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
        sigKey: goodKey,
        sigAlg: 'RS256' as unknown as 'HS256',
      }),
    ).rejects.toThrow(/unsupported signature algorithm/)
  })
})

describe('layer2 — verify validation', () => {
  it('rejects empty sigKey', async () => {
    await expect(
      verifyShortLivedToken('anything', {
        sigKey: new Uint8Array(0),
        sigAlg: AlgHS256,
      }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects EdDSA at verify time (v1 gap)', async () => {
    await expect(
      verifyShortLivedToken('anything', {
        sigKey: goodKey,
        sigAlg: AlgEdDSA,
      }),
    ).rejects.toMatchObject({ kind: 'infra-failure' })
  })

  it('rejects unknown algorithm at verify time', async () => {
    await expect(
      verifyShortLivedToken('anything', {
        sigKey: goodKey,
        sigAlg: 'RS256' as unknown as 'HS256',
      }),
    ).rejects.toThrow(/unsupported signature algorithm/)
  })

  it('rejects malformed token', async () => {
    await expect(
      verifyShortLivedToken('not.a.jwt', { sigKey: goodKey, sigAlg: AlgHS256 }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })
})

describe('layer2 — security invariants', () => {
  it('rejects wrong-key signature', async () => {
    const token = await issueShortLivedToken({
      claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
      sigKey: goodKey,
      sigAlg: AlgHS256,
    })
    await expect(
      verifyShortLivedToken(token, {
        sigKey: new Uint8Array(32).fill(0),
        sigAlg: AlgHS256,
      }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects tampered payload', async () => {
    const token = await issueShortLivedToken({
      claims: { uid: 'u', documentName: '', role: '', permissionEpoch: 0 },
      sigKey: goodKey,
      sigAlg: AlgHS256,
    })
    const parts = token.split('.')
    // Flip a char in the payload segment; signature no longer matches.
    const bad = parts[1]!.slice(0, -1) + (parts[1]!.slice(-1) === 'A' ? 'B' : 'A')
    const tampered = `${parts[0]}.${bad}.${parts[2]}`
    await expect(
      verifyShortLivedToken(tampered, { sigKey: goodKey, sigAlg: AlgHS256 }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects expired tokens', async () => {
    // Sign with a manual jose call to get a past exp — issueShortLivedToken
    // requires ttlSeconds > 0.
    const nowSec = Math.floor(Date.now() / 1000)
    const past = nowSec - 60
    const token = await new SignJWT({ uid: 'u' })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime(past)
      .sign(goodKey)
    await expect(
      verifyShortLivedToken(token, { sigKey: goodKey, sigAlg: AlgHS256 }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects HS512 tokens (alg-confusion defense)', async () => {
    // Craft a HS512 token that the verifier should reject even though the
    // secret material is the same length. jose's `algorithms: ['HS256']`
    // whitelist enforces this.
    const bigKey = new Uint8Array(64).fill(9)
    const token = await new SignJWT({ uid: 'u' })
      .setProtectedHeader({ alg: 'HS512' })
      .setExpirationTime('5m')
      .sign(bigKey)
    await expect(
      verifyShortLivedToken(token, { sigKey: bigKey, sigAlg: AlgHS256 }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects alg=none tokens', async () => {
    // Header + body base64url without a signature; jose refuses this.
    const header = Buffer.from('{"alg":"none"}').toString('base64url')
    const payload = Buffer.from(
      JSON.stringify({ uid: 'u', exp: Math.floor(Date.now() / 1000) + 300 }),
    ).toString('base64url')
    const evil = `${header}.${payload}.`
    await expect(
      verifyShortLivedToken(evil, { sigKey: goodKey, sigAlg: AlgHS256 }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })

  it('rejects tokens missing uid claim', async () => {
    // Issue a token with an empty uid via jose directly (issueShortLivedToken
    // would refuse).
    const token = await new SignJWT({ document_name: 'd' })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('5m')
      .sign(goodKey)
    await expect(
      verifyShortLivedToken(token, { sigKey: goodKey, sigAlg: AlgHS256 }),
    ).rejects.toMatchObject({ kind: 'invalid-credential' })
  })
})
