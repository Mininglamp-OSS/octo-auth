import { describe, expect, it } from 'vitest'

import {
  BearerScheme,
  HeaderAuthorization,
  HeaderToken,
  KindAPIKey,
  KindBot,
  KindSession,
  OctoAuthError,
  extractCredential,
  validateAPIKey,
  validateBotToken,
} from '../src/index.js'

describe('extractCredential', () => {
  it('exports the header / scheme constants', () => {
    expect(HeaderAuthorization).toBe('authorization')
    expect(HeaderToken).toBe('token')
    expect(BearerScheme).toBe('Bearer')
  })

  it('reads Authorization: Bearer token', () => {
    const c = extractCredential({ headers: { authorization: 'Bearer bf_abc' } })
    expect(c).toEqual({ kind: KindBot, raw: 'bf_abc' })
  })

  it('is case-insensitive on the Bearer scheme (RFC 7235)', () => {
    const c = extractCredential({ headers: { authorization: 'BEARER bf_abc' } })
    expect(c.raw).toBe('bf_abc')
    const c2 = extractCredential({ headers: { authorization: 'bearer bf_abc' } })
    expect(c2.raw).toBe('bf_abc')
  })

  it('falls back to token header when Authorization is missing', () => {
    const c = extractCredential({ headers: { token: 'plainsession' } })
    expect(c).toEqual({ kind: KindSession, raw: 'plainsession' })
  })

  it('falls back to token header when Authorization is non-Bearer', () => {
    const c = extractCredential({
      headers: { authorization: 'Basic ZGVtbw==', token: 'plainsession' },
    })
    expect(c.raw).toBe('plainsession')
  })

  it('finds headers case-insensitively (non-lowercased key)', () => {
    // Some environments preserve original case; extractCredential should
    // still find the header by scanning keys.
    const c = extractCredential({ headers: { Authorization: 'Bearer bf_abc' } })
    expect(c.raw).toBe('bf_abc')
  })

  it('coerces array header values to the first element', () => {
    const c = extractCredential({
      headers: { authorization: ['Bearer bf_first', 'Bearer bf_second'] },
    })
    expect(c.raw).toBe('bf_first')
  })

  it('throws invalid-credential when no header is present', () => {
    try {
      extractCredential({ headers: {} })
      expect.fail('should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).kind).toBe('invalid-credential')
    }
  })

  it('throws invalid-credential when req or headers is nullish', () => {
    expect(() =>
      extractCredential(null as unknown as { headers: {} }),
    ).toThrow(OctoAuthError)
    expect(() =>
      extractCredential({ headers: null as unknown as {} }),
    ).toThrow(OctoAuthError)
  })

  it('throws invalid-credential when the resolved credential is empty', () => {
    // Authorization: Bearer with nothing after the scheme resolves to "".
    expect(() =>
      extractCredential({ headers: { authorization: 'Bearer ' } }),
    ).toThrow(OctoAuthError)
  })

  it('trims whitespace around the token', () => {
    const c = extractCredential({
      headers: { authorization: '  Bearer   bf_padded   ' },
    })
    expect(c.raw).toBe('bf_padded')
  })

  it('classifies apikey / bot / session correctly at extraction time', () => {
    const uk = extractCredential({
      headers: { token: 'uk_' + 'x'.repeat(32) },
    })
    expect(uk.kind).toBe(KindAPIKey)
    const bf = extractCredential({ headers: { token: 'bf_abc' } })
    expect(bf.kind).toBe(KindBot)
    const app = extractCredential({ headers: { token: 'app_xyz' } })
    expect(app.kind).toBe(KindBot)
    const s = extractCredential({ headers: { token: 'plain-32-hex-uuid-token' } })
    expect(s.kind).toBe(KindSession)
  })
})

describe('validateAPIKey', () => {
  it('accepts a well-formed uk_ key', () => {
    expect(() => validateAPIKey('uk_' + 'a'.repeat(32))).not.toThrow()
  })

  it('rejects when missing uk_ prefix', () => {
    try {
      validateAPIKey('nk_' + 'a'.repeat(32))
    } catch (err) {
      expect(err).toBeInstanceOf(OctoAuthError)
      expect((err as OctoAuthError).verifier).toBe(KindAPIKey)
      expect((err as Error).message).toMatch(/missing uk_ prefix/)
    }
  })

  it('rejects too-short keys', () => {
    expect(() => validateAPIKey('uk_short')).toThrow(/too short/)
  })
})

describe('validateBotToken', () => {
  it('accepts bf_ and app_ prefixes with a body', () => {
    expect(() => validateBotToken('bf_body')).not.toThrow()
    expect(() => validateBotToken('app_body')).not.toThrow()
  })

  it('rejects prefix-only bf_ token', () => {
    // Length guard is `len <= len(PrefixBF)` (3 chars); 'bf_' hits exactly,
    // 'app_' does not because len('app_')=4 > 3. The app_ realm is instead
    // rejected inside botTokenVerifier.verify at runtime.
    expect(() => validateBotToken('bf_')).toThrow(/prefix only/)
  })

  it('rejects tokens missing both bot prefixes', () => {
    expect(() => validateBotToken('random')).toThrow(/missing bf_/)
  })
})
