/**
 * sessionVerifier — resolves human-session tokens (32-hex UUID, no prefix).
 *
 * See design doc §4.2 and Go SDK's session_verifier.go. Mirrors Go semantics
 * exactly: empty short-circuit, cache under "s:" prefix, POST /v1/auth/verify
 * with optional ?include=context, empty uid → invalid-credential.
 */

import { OctoAuthError } from './errors.js'
import type { Config } from './config.js'
import { applyDefaults } from './config.js'
import type { Principal, PrincipalContext, Verifier, VerifyOptions } from './verifier.js'
import { KindSession } from './verifier.js'
import { VerifyContext, doVerifyRequest } from './http-verifier.js'

const SESSION_ENDPOINT = '/v1/auth/verify'

/**
 * OwnedBot is one entry of the session response's owned_bots array.
 * Mirrors server-side `ownedBot` in modules/user/api.go.
 */
export interface OwnedBot {
  uid: string
  name: string
}

interface SessionResponse {
  uid?: string
  name?: string
  role?: string
  owned_bots?: OwnedBot[]
  context_included?: boolean
  spaces?: string[]
  owned_bots_by_space?: Record<string, string[]>
}

/**
 * newSessionVerifier builds a Verifier that resolves session tokens against
 * octo-server. Callers wanting the three verifiers to share cache / metrics
 * pass the same Config to each constructor; applyDefaults is idempotent.
 */
export function newSessionVerifier(cfg: Config): Verifier {
  const resolved = applyDefaults(cfg)
  return {
    kind: KindSession,
    async verify(credential: string, opts?: VerifyOptions): Promise<Principal> {
      if (credential === '') {
        throw new OctoAuthError('invalid-credential', 'empty credential', {
          verifier: KindSession,
        })
      }
      const vc = new VerifyContext(
        resolved,
        KindSession,
        's:',
        credential,
        resolved.sessionTtlMs,
      )
      const cached = await vc.lookupCache()
      if (cached.hit) {
        return vc.recordCacheHit(cached.principal, cached.error)
      }
      vc.recordCacheMiss()

      const endpoint = resolved.requestIncludeContext
        ? SESSION_ENDPOINT + '?include=context'
        : SESSION_ENDPOINT
      try {
        const raw = await doVerifyRequest(
          resolved,
          endpoint,
          { token: credential },
          KindSession,
          opts?.signal,
        )
        const resp = raw as SessionResponse
        if (!resp || !resp.uid) {
          throw new OctoAuthError(
            'invalid-credential',
            'verify response missing uid',
            { verifier: KindSession },
          )
        }
        const p: Principal = {
          kind: KindSession,
          uid: resp.uid,
          name: resp.name ?? '',
          role: resp.role ?? '',
          relatedUids: buildSessionRelated(resp.uid, resp.owned_bots),
          context: sessionContextFromResponse(
            resp,
            resolved.requestIncludeContext,
          ),
        }
        return vc.finalizeSuccess(p)
      } catch (err) {
        return vc.finalizeError(err)
      }
    },
  }
}

/**
 * buildSessionRelated returns [self, ...ownedBotUIDs] with duplicates dropped
 * while preserving order.
 */
function buildSessionRelated(
  self: string,
  ownedBots: OwnedBot[] | undefined,
): string[] {
  const out: string[] = [self]
  const seen = new Set<string>([self])
  if (ownedBots) {
    for (const b of ownedBots) {
      if (b.uid === '' || seen.has(b.uid)) continue
      out.push(b.uid)
      seen.add(b.uid)
    }
  }
  return out
}

/**
 * sessionContextFromResponse maps the response's context_included + spaces +
 * owned_bots_by_space fields into a PrincipalContext.
 *
 * If include=context was not requested → not-requested. Otherwise:
 *   - context_included === undefined → unknown-server
 *     Ambiguous: server is either pre-v2, or v3+ that declined this call
 *     (the omitempty tag on the server side erases explicit false).
 *   - context_included === false     → not-included
 *     Currently unreachable against server v3 (omitempty erases false);
 *     preserved for a future server that drops omitempty.
 *   - context_included === true      → included (fields copied)
 */
function sessionContextFromResponse(
  resp: SessionResponse,
  includeRequested: boolean,
): PrincipalContext {
  if (!includeRequested) return { kind: 'not-requested' }
  if (resp.context_included === undefined) return { kind: 'unknown-server' }
  if (resp.context_included === false) return { kind: 'not-included' }
  const ctx: PrincipalContext = { kind: 'included' }
  if (resp.spaces !== undefined) ctx.spaces = resp.spaces
  if (resp.owned_bots_by_space !== undefined) {
    ctx.ownedBotsBySpace = resp.owned_bots_by_space
  }
  return ctx
}
