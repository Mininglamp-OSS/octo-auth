import { describe, expect, it } from 'vitest'

import {
  KindAPIKey,
  KindBot,
  KindSession,
  MinAPIKeyLength,
  OctoAuthError,
  PrefixApp,
  PrefixBF,
  PrefixUK,
  classifyCredential,
  newMultiVerifier,
  newSessionVerifier,
  type Principal,
  type Verifier,
} from '../src/index.js'

describe('kind constants', () => {
  it('exposes stable string literals', () => {
    expect(KindSession).toBe('session')
    expect(KindBot).toBe('bot')
    expect(KindAPIKey).toBe('apikey')
    expect(PrefixUK).toBe('uk_')
    expect(PrefixBF).toBe('bf_')
    expect(PrefixApp).toBe('app_')
    expect(MinAPIKeyLength).toBe(35)
  })
})

describe('classifyCredential dispatch table', () => {
  const uk35 = 'uk_' + 'a'.repeat(32) // total 35
  const uk34 = 'uk_' + 'a'.repeat(31) // total 34 (short by 1)

  const cases: Array<{ input: string; expect: 'apikey' | 'bot' | 'session' | 'throws' }> = [
    { input: uk35, expect: 'apikey' },
    { input: uk34, expect: 'throws' },
    { input: 'bf_botsomething', expect: 'bot' },
    { input: 'app_reserved', expect: 'bot' },
    { input: 'abcdef1234567890abcdef1234567890', expect: 'session' },
    { input: '  ', expect: 'session' },
    { input: '', expect: 'throws' },
  ]

  for (const c of cases) {
    it(`input=${JSON.stringify(c.input.slice(0, 12))} → ${c.expect}`, () => {
      if (c.expect === 'throws') {
        try {
          classifyCredential(c.input)
          expect.fail('should have thrown')
        } catch (err) {
          expect(err).toBeInstanceOf(OctoAuthError)
          expect((err as OctoAuthError).kind).toBe('invalid-credential')
        }
      } else {
        expect(classifyCredential(c.input)).toBe(c.expect)
      }
    })
  }

  it('too-short uk_ tags the error with the apikey verifier', () => {
    try {
      classifyCredential('uk_short')
    } catch (err) {
      expect((err as OctoAuthError).verifier).toBe(KindAPIKey)
    }
  })
})

describe('newMultiVerifier dispatch', () => {
  const makeStub = (kind: 'session' | 'bot' | 'apikey'): Verifier => ({
    kind,
    async verify(): Promise<Principal> {
      return { kind, uid: 'u-' + kind, context: { kind: 'not-requested' } }
    },
  })

  it('routes uk_ to apikey child', async () => {
    const m = newMultiVerifier(makeStub('apikey'), makeStub('bot'), makeStub('session'))
    const p = await m.verify('uk_' + 'x'.repeat(32))
    expect(p.kind).toBe('apikey')
  })

  it('routes bf_ to bot child', async () => {
    const m = newMultiVerifier(makeStub('apikey'), makeStub('bot'), makeStub('session'))
    const p = await m.verify('bf_botxyz')
    expect(p.kind).toBe('bot')
  })

  it('routes app_ to bot child (reserved hook)', async () => {
    const m = newMultiVerifier(makeStub('apikey'), makeStub('bot'), makeStub('session'))
    const p = await m.verify('app_something')
    expect(p.kind).toBe('bot')
  })

  it('routes bare token to session child', async () => {
    const m = newMultiVerifier(makeStub('apikey'), makeStub('bot'), makeStub('session'))
    const p = await m.verify('plainsession')
    expect(p.kind).toBe('session')
  })

  it('rejects when the routed realm has no registered child', async () => {
    // Only session registered; bf_ tries to dispatch to bot → throws.
    const m = newMultiVerifier(makeStub('session'))
    await expect(m.verify('bf_notregistered')).rejects.toBeInstanceOf(
      OctoAuthError,
    )
  })

  it('exposes a "multi" facade kind (not a real realm)', () => {
    const m = newMultiVerifier(makeStub('session'))
    expect(m.kind).toBe('multi')
  })

  it('register() replaces the child for a kind and returns the receiver', async () => {
    const first: Verifier = {
      kind: 'session',
      async verify() {
        return { kind: 'session', uid: 'first', context: { kind: 'not-requested' } }
      },
    }
    const second: Verifier = {
      kind: 'session',
      async verify() {
        return { kind: 'session', uid: 'second', context: { kind: 'not-requested' } }
      },
    }
    const m = newMultiVerifier(first)
    const same = m.register(second)
    expect(same).toBe(m)
    const p = await m.verify('token')
    expect(p.uid).toBe('second')
  })

  it('ignores nullish children on construction and register', () => {
    // Nullish handling is defensive; passing undefined mid-list shouldn't blow up.
    const m = newMultiVerifier(
      undefined as unknown as Verifier,
      newSessionVerifier({ baseUrl: 'https://octo.test' }),
    )
    // register(nullish) is a no-op but still returns the receiver.
    expect(m.register(null as unknown as Verifier)).toBe(m)
  })

  it('rejects empty credential up front', async () => {
    const m = newMultiVerifier(newSessionVerifier({ baseUrl: 'https://octo.test' }))
    await expect(m.verify('')).rejects.toBeInstanceOf(OctoAuthError)
  })
})
