/**
 * Principal.clone helper.
 *
 * In TS we use a standalone function rather than a method-on-interface because
 * `Principal` is a plain interface with readonly reference fields — middleware
 * layers call `clonePrincipal(p)` before mutating spaceId.
 *
 * The three reference-typed fields — relatedUids, context.spaces,
 * context.ownedBotsBySpace — are copied element-wise; scalars are
 * shallow-copied by object spread.
 *
 * Nullish-safe: `clonePrincipal(undefined)` returns undefined.
 */

import type { Principal, PrincipalContext } from './verifier.js'

export function clonePrincipal(p: Principal): Principal
export function clonePrincipal(p: undefined): undefined
export function clonePrincipal(p: Principal | undefined): Principal | undefined
export function clonePrincipal(
  p: Principal | undefined,
): Principal | undefined {
  if (p === undefined) return undefined
  const dst: Principal = { ...p, context: cloneContext(p.context) }
  if (p.relatedUids !== undefined) {
    dst.relatedUids = [...p.relatedUids]
  }
  return dst
}

function cloneContext(c: PrincipalContext): PrincipalContext {
  const dst: PrincipalContext = { kind: c.kind }
  if (c.spaces !== undefined) {
    dst.spaces = [...c.spaces]
  }
  if (c.ownedBotsBySpace !== undefined) {
    const map: Record<string, readonly string[]> = {}
    for (const k of Object.keys(c.ownedBotsBySpace)) {
      const arr = c.ownedBotsBySpace[k]
      map[k] = arr === undefined ? [] : [...arr]
    }
    dst.ownedBotsBySpace = map
  }
  return dst
}
