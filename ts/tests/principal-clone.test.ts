import { describe, expect, it } from 'vitest'

import { KindSession, clonePrincipal, type Principal } from '../src/index.js'

describe('clonePrincipal', () => {
  it('returns undefined when input is undefined', () => {
    expect(clonePrincipal(undefined)).toBeUndefined()
  })

  it('deep-copies relatedUids so mutation does not leak', () => {
    const src: Principal = {
      kind: KindSession,
      uid: 'u1',
      relatedUids: ['u1', 'bot1'],
      context: { kind: 'not-requested' },
    }
    const dst = clonePrincipal(src)
    expect(dst.relatedUids).not.toBe(src.relatedUids)
    ;(dst.relatedUids as string[]).push('leak')
    expect(src.relatedUids).toEqual(['u1', 'bot1'])
  })

  it('deep-copies context.spaces', () => {
    const src: Principal = {
      kind: KindSession,
      uid: 'u1',
      context: { kind: 'included', spaces: ['s1', 's2'] },
    }
    const dst = clonePrincipal(src)
    expect(dst.context).not.toBe(src.context)
    expect(dst.context.spaces).not.toBe(src.context.spaces)
    ;(dst.context.spaces as string[]).push('s3')
    expect(src.context.spaces).toEqual(['s1', 's2'])
  })

  it('deep-copies context.ownedBotsBySpace', () => {
    const src: Principal = {
      kind: KindSession,
      uid: 'u1',
      context: {
        kind: 'included',
        ownedBotsBySpace: { s1: ['bot1', 'bot2'], s2: [] },
      },
    }
    const dst = clonePrincipal(src)
    expect(dst.context.ownedBotsBySpace).not.toBe(src.context.ownedBotsBySpace)
    expect(dst.context.ownedBotsBySpace?.['s1']).not.toBe(
      src.context.ownedBotsBySpace?.['s1'],
    )
    // Mutate the clone's inner array — source stays intact.
    ;(dst.context.ownedBotsBySpace!['s1'] as string[]).push('leak')
    expect(src.context.ownedBotsBySpace!['s1']).toEqual(['bot1', 'bot2'])
  })

  it('handles undefined inner slices in ownedBotsBySpace defensively', () => {
    const src: Principal = {
      kind: KindSession,
      uid: 'u1',
      context: {
        kind: 'included',
        // Coerce a missing-array value; SDK contract normally guarantees
        // string[] but we want to prove clone doesn't crash if it ever isn't.
        ownedBotsBySpace: { s1: undefined as unknown as string[] },
      },
    }
    const dst = clonePrincipal(src)
    expect(dst.context.ownedBotsBySpace?.['s1']).toEqual([])
  })

  it('preserves scalar fields via shallow copy', () => {
    const src: Principal = {
      kind: KindSession,
      uid: 'u1',
      name: 'alice',
      role: 'writer',
      spaceId: 's1',
      ownerUid: 'ou',
      ownerName: 'on',
      context: { kind: 'not-requested' },
    }
    const dst = clonePrincipal(src)
    expect(dst).toEqual(src)
    expect(dst).not.toBe(src)
  })
})
