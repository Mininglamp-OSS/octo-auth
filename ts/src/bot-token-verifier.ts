/**
 * botTokenVerifier — resolves bot tokens (bf_-prefixed; app_ reserved).
 *
 * See design doc §4.2 and Go SDK's bot_token_verifier.go. Never sends
 * include=context (server response is already space-authoritative). Empty
 * bot_uid or space_id collapses to invalid-credential, matching fleet's
 * middleware.go behavior. app_ tokens are short-circuited without any HTTP
 * call — the classification hook remains so v2 can add support additively.
 */

import { OctoAuthError } from './errors.js'
import type { Config } from './config.js'
import { applyDefaults } from './config.js'
import type { Principal, Verifier, VerifyOptions } from './verifier.js'
import { KindBot, PrefixApp } from './verifier.js'
import { VerifyContext, doVerifyRequest } from './http-verifier.js'

const BOT_ENDPOINT = '/v1/auth/verify-bot'

interface BotResponse {
  bot_uid?: string
  bot_name?: string
  role?: string
  owner_uid?: string
  owner_name?: string
  space_id?: string
}

/**
 * newBotTokenVerifier builds a Verifier for bot tokens. cfg is patched in
 * place with defaults.
 */
export function newBotTokenVerifier(cfg: Config): Verifier {
  const resolved = applyDefaults(cfg)
  return {
    kind: KindBot,
    async verify(credential: string, opts?: VerifyOptions): Promise<Principal> {
      if (credential === '') {
        throw new OctoAuthError('invalid-credential', 'empty credential', {
          verifier: KindBot,
        })
      }
      // v1: reject app_ before touching the network. Dispatch layer still
      // routes app_ here so a future SDK release can add support without
      // client-side breakage.
      if (credential.startsWith(PrefixApp)) {
        throw new OctoAuthError(
          'invalid-credential',
          'app_ tokens are reserved and not supported in this SDK version',
          { verifier: KindBot },
        )
      }
      const vc = new VerifyContext(
        resolved,
        KindBot,
        'b:',
        credential,
        resolved.botTtlMs,
      )
      const cached = await vc.lookupCache()
      if (cached.hit) {
        return vc.recordCacheHit(cached.principal, cached.error)
      }
      vc.recordCacheMiss()

      try {
        const raw = await doVerifyRequest(
          resolved,
          BOT_ENDPOINT,
          { bot_token: credential },
          KindBot,
          opts?.signal,
        )
        const resp = raw as BotResponse
        if (!resp || !resp.bot_uid || !resp.space_id) {
          throw new OctoAuthError(
            'invalid-credential',
            'verify-bot response missing uid or space_id',
            { verifier: KindBot },
          )
        }
        const p: Principal = {
          kind: KindBot,
          uid: resp.bot_uid,
          name: resp.bot_name ?? '',
          role: resp.role ?? '',
          spaceId: resp.space_id,
          ownerUid: resp.owner_uid ?? '',
          ownerName: resp.owner_name ?? '',
          relatedUids: [resp.bot_uid],
          context: { kind: 'not-requested' },
        }
        return vc.finalizeSuccess(p)
      } catch (err) {
        return vc.finalizeError(err)
      }
    },
  }
}
