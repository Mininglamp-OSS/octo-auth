/**
 * userKeyVerifier — resolves user API keys (uk_-prefixed, length >= 35).
 *
 * Short-circuits obviously malformed keys locally to shield octo-server from
 * wave-attack traffic. include=context is sent by default; the `spaces` field
 * of the PrincipalContext is derived from the sorted owned_bots map keys so
 * the output is deterministic across cache hits.
 */

import { OctoAuthError } from './errors.js'
import type { Config } from './config.js'
import { applyDefaults } from './config.js'
import type { Principal, PrincipalContext, Verifier, VerifyOptions } from './verifier.js'
import { KindAPIKey } from './verifier.js'
import { VerifyContext, doVerifyRequest } from './http-verifier.js'
import { validateAPIKey } from './extract.js'

const API_KEY_ENDPOINT = '/v1/auth/verify-api-key'

interface APIKeyResponse {
  uid?: string
  space_id?: string
  context_included?: boolean
  owned_bots?: Record<string, string[]>
}

/**
 * newUserKeyVerifier builds a Verifier for user API keys. cfg is patched in
 * place with defaults.
 */
export function newUserKeyVerifier(cfg: Config): Verifier {
  const resolved = applyDefaults(cfg)
  return {
    kind: KindAPIKey,
    async verify(credential: string, opts?: VerifyOptions): Promise<Principal> {
      if (credential === '') {
        throw new OctoAuthError('invalid-credential', 'empty credential', {
          verifier: KindAPIKey,
        })
      }
      // Local short-circuit for obvious malformation. Throws OctoAuthError.
      validateAPIKey(credential)
      const vc = new VerifyContext(
        resolved,
        KindAPIKey,
        'k:',
        credential,
        resolved.apiKeyTtlMs,
      )
      const cached = await vc.lookupCache()
      if (cached.hit) {
        return vc.recordCacheHit(cached.principal, cached.error)
      }
      vc.recordCacheMiss()

      const endpoint = resolved.requestIncludeContext
        ? API_KEY_ENDPOINT + '?include=context'
        : API_KEY_ENDPOINT
      try {
        const raw = await doVerifyRequest(
          resolved,
          endpoint,
          { api_key: credential },
          KindAPIKey,
          opts?.signal,
        )
        const resp = raw as APIKeyResponse
        if (!resp || !resp.uid || !resp.space_id) {
          throw new OctoAuthError(
            'invalid-credential',
            'verify-api-key response missing uid or space_id',
            { verifier: KindAPIKey },
          )
        }
        const p: Principal = {
          kind: KindAPIKey,
          uid: resp.uid,
          spaceId: resp.space_id,
          context: apiKeyContextFromResponse(
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

function apiKeyContextFromResponse(
  resp: APIKeyResponse,
  includeRequested: boolean,
): PrincipalContext {
  if (!includeRequested) return { kind: 'not-requested' }
  if (resp.context_included === undefined) return { kind: 'unknown-server' }
  if (resp.context_included === false) return { kind: 'not-included' }
  const ctx: PrincipalContext = { kind: 'included' }
  if (resp.owned_bots !== undefined) {
    ctx.ownedBotsBySpace = resp.owned_bots
    ctx.spaces = spacesFromOwnedBots(resp.owned_bots)
  }
  return ctx
}

/**
 * spacesFromOwnedBots returns the sorted list of map keys. Sorting keeps the
 * output deterministic across cache hits.
 */
function spacesFromOwnedBots(owned: Record<string, string[]>): string[] {
  const keys = Object.keys(owned)
  keys.sort()
  return keys
}
