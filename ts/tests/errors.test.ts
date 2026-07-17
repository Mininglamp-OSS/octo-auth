import { describe, expect, it } from 'vitest'

import {
  BODY_DISABLED,
  BODY_FORBIDDEN,
  BODY_INTERNAL,
  BODY_UNAUTHORIZED,
  BODY_UPSTREAM_UNAVAILABLE,
  OctoAuthError,
  defaultErrorMapper,
} from '../src/index.js'

describe('OctoAuthError', () => {
  it('sets name, kind, message, and native cause', () => {
    const cause = new Error('root')
    const err = new OctoAuthError('invalid-credential', 'bad token', {
      cause,
      verifier: 'session',
    })
    expect(err).toBeInstanceOf(Error)
    expect(err).toBeInstanceOf(OctoAuthError)
    expect(err.name).toBe('OctoAuthError')
    expect(err.kind).toBe('invalid-credential')
    expect(err.message).toBe('bad token')
    expect(err.verifier).toBe('session')
    expect(err.cause).toBe(cause)
  })

  it('defaults message to the kind when unset', () => {
    const err = new OctoAuthError('disabled')
    expect(err.message).toBe('disabled')
  })

  it('sentinel factories construct proper kinds', () => {
    expect(OctoAuthError.invalidCredential('x').kind).toBe('invalid-credential')
    expect(OctoAuthError.disabled('x').kind).toBe('disabled')
    expect(OctoAuthError.infraFailure('x').kind).toBe('infra-failure')
    expect(OctoAuthError.forbidden('x').kind).toBe('forbidden')
  })

  it('leaves verifier undefined when not provided', () => {
    const err = new OctoAuthError('disabled', 'x')
    expect(err.verifier).toBeUndefined()
  })

  it('preserves the prototype chain across subclassing (instanceof)', () => {
    // Subclass simulates downstream extensions.
    class MyError extends OctoAuthError {
      readonly extra = 42
    }
    const e = new MyError('forbidden', 'yo')
    expect(e).toBeInstanceOf(MyError)
    expect(e).toBeInstanceOf(OctoAuthError)
    expect(e).toBeInstanceOf(Error)
  })
})

describe('defaultErrorMapper', () => {
  const cases: Array<{ kind: 'invalid-credential' | 'disabled' | 'infra-failure' | 'forbidden' | 'pre-v2-server'; status: number; body: string }> = [
    { kind: 'invalid-credential', status: 401, body: BODY_UNAUTHORIZED },
    { kind: 'disabled', status: 403, body: BODY_DISABLED },
    { kind: 'infra-failure', status: 503, body: BODY_UPSTREAM_UNAVAILABLE },
    { kind: 'forbidden', status: 403, body: BODY_FORBIDDEN },
    { kind: 'pre-v2-server', status: 500, body: BODY_INTERNAL },
  ]
  for (const c of cases) {
    it(`${c.kind} → ${c.status} ${c.body}`, () => {
      const r = defaultErrorMapper(new OctoAuthError(c.kind))
      expect(r.status).toBe(c.status)
      expect(r.body).toBe(c.body)
    })
  }

  it('falls through to 500 internal for non-OctoAuthError', () => {
    const r = defaultErrorMapper(new Error('random'))
    expect(r).toEqual({ status: 500, body: BODY_INTERNAL })
  })

  it('handles thrown strings / nullish inputs defensively', () => {
    expect(defaultErrorMapper('kaboom').status).toBe(500)
    expect(defaultErrorMapper(undefined).status).toBe(500)
    expect(defaultErrorMapper(null).status).toBe(500)
  })

  it('anti-enumeration: two invalid-credential errors with different messages produce byte-identical response', () => {
    const a = defaultErrorMapper(new OctoAuthError('invalid-credential', 'unknown token'))
    const b = defaultErrorMapper(
      new OctoAuthError('invalid-credential', 'expired session token from user x'),
    )
    expect(a.status).toBe(b.status)
    expect(a.body).toBe(b.body)
    expect(a.body).toBe(BODY_UNAUTHORIZED)
  })

  it('anti-enumeration: two disabled errors produce byte-identical response', () => {
    const a = defaultErrorMapper(new OctoAuthError('disabled', 'user banned'))
    const b = defaultErrorMapper(new OctoAuthError('disabled', 'realm turned off'))
    expect(a.body).toBe(b.body)
    expect(a.body).toBe(BODY_DISABLED)
  })
})

describe('exported body constants match design doc §5.2', () => {
  it('are byte-identical to the reference strings', () => {
    expect(BODY_UNAUTHORIZED).toBe('{"error":"unauthorized"}')
    expect(BODY_DISABLED).toBe('{"error":"disabled"}')
    expect(BODY_UPSTREAM_UNAVAILABLE).toBe('{"error":"upstream_unavailable"}')
    expect(BODY_FORBIDDEN).toBe('{"error":"forbidden"}')
    expect(BODY_INTERNAL).toBe('{"error":"internal"}')
  })
})
