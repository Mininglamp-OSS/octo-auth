/** New Bot-only identity/delegation resolver. Legacy verifiers are unchanged. */
import type { Config } from './config.js'
import { applyDefaults } from './config.js'
import { OctoAuthError } from './errors.js'
import {
  logVerifyResult,
  readTextBounded,
  VERIFY_RESULT_AUTH_ERR,
  VERIFY_RESULT_INFRA,
  VERIFY_RESULT_MISS_OK,
} from './http-verifier.js'
import { KindBot, PrefixBF } from './verifier.js'

const ENDPOINT = '/v1/internal/auth/resolve'
const MAX_BODY_BYTES = 1 << 20
const DECISION_ID_PATTERN = /^[0-9a-f]{32}$/

export type BotResolveMode = 'AS_BOT' | 'OBO'

export interface ResolveRequest {
  mode: BotResolveMode
  spaceId: string
  action?: string
  resource?: { type: string; id: string }
}

export interface ResolvedIdentity {
  uid: string
  kind: 'BOT' | 'HUMAN'
  spaceId: string
}

export interface ResolvedDelegation {
  grantId: number
  matchedScope: 'ALL'
  policyVersion: number
  action: string
  decisionId: string
}

export interface ResolvedPrincipal {
  mode: BotResolveMode
  actor: ResolvedIdentity
  subject: ResolvedIdentity
  delegation?: ResolvedDelegation
}

export interface BotResolver {
  resolve(credential: string, request: ResolveRequest, signal?: AbortSignal): Promise<ResolvedPrincipal>
}

interface WireIdentity { uid?: string; kind?: string; space_id?: string }
interface WireDelegation {
  grant_id?: number
  matched_scope?: string
  policy_version?: number
  action?: string
  decision_id?: string
}
interface WirePrincipal {
  mode?: string
  actor?: WireIdentity
  subject?: WireIdentity
  delegation?: WireDelegation
}

function requestError(message: string): OctoAuthError {
  return new OctoAuthError('invalid-request', message, { verifier: KindBot })
}

function protocolError(message: string, cause?: unknown): OctoAuthError {
  return new OctoAuthError('infra-failure', message, { verifier: KindBot, cause })
}

function wireError(status: number, text: string): OctoAuthError {
  let envelope: { code?: string; request_id?: string }
  try { envelope = JSON.parse(text) as typeof envelope } catch (err) {
    return protocolError('invalid Resolve error envelope', err)
  }
  if (typeof envelope?.request_id !== 'string' || envelope.request_id.length === 0) {
    return protocolError('Resolve error response missing request_id')
  }
  const code = envelope?.code
  let kind: 'invalid-request' | 'invalid-credential' | 'disabled' | 'forbidden' | 'infra-failure' = 'infra-failure'
  let valid = false
  switch (code) {
    case 'invalid_mode':
    case 'invalid_request':
    case 'missing_space_id':
      kind = 'invalid-request'; valid = status === 400; break
    case 'invalid_credential':
      kind = 'invalid-credential'; valid = status === 401; break
    case 'disabled':
      kind = 'disabled'; valid = status === 403; break
    case 'space_not_allowed':
    case 'delegation_denied':
    case 'action_not_allowed':
      kind = 'forbidden'; valid = status === 403; break
    case 'infra_failure':
      kind = 'infra-failure'; valid = status === 503; break
  }
  if (!valid) return protocolError(`unexpected Resolve status/code: ${status}/${code ?? ''}`)
  return new OctoAuthError(kind, 'Resolve rejected', {
    verifier: KindBot,
    code,
    requestId: envelope.request_id,
  })
}

function readIdentity(value: WireIdentity | undefined, spaceId: string): ResolvedIdentity | undefined {
  if (!value?.uid || value.space_id !== spaceId || (value.kind !== 'BOT' && value.kind !== 'HUMAN')) {
    return undefined
  }
  return { uid: value.uid, kind: value.kind, spaceId: value.space_id }
}

export function newBotResolver(cfg: Config): BotResolver {
  const resolved = applyDefaults(cfg)

  return {
    async resolve(credential, request, signal) {
      const started = Date.now()
      let result = VERIFY_RESULT_MISS_OK
      try {
      if (!credential.startsWith(PrefixBF) || credential.length <= PrefixBF.length || credential.trim() !== credential) {
        throw new OctoAuthError('invalid-credential', 'unsupported or empty Bot credential', { verifier: KindBot })
      }
      if (!request.spaceId?.trim()) throw requestError('spaceId is required')
      if (request.mode === 'AS_BOT') {
        if ((request.action !== undefined && request.action !== '') || request.resource !== undefined) {
          throw requestError('AS_BOT cannot carry action or resource')
        }
      } else if (request.mode === 'OBO') {
        if (!request.action?.trim()) throw requestError('OBO requires action')
      } else {
        throw requestError('invalid Bot resolve mode')
      }

      const timeout = AbortSignal.timeout(resolved.timeoutMs)
      const combined = signal ? AbortSignal.any([signal, timeout]) : timeout
      let response: Response
      try {
        response = await resolved.fetch(resolved.baseUrl + ENDPOINT, {
          method: 'POST', redirect: 'error', signal: combined,
          headers: {
            'Content-Type': 'application/json', Accept: 'application/json',
            'Cache-Control': 'no-store',
          },
          body: JSON.stringify({
            bot_token: credential, mode: request.mode, space_id: request.spaceId,
            ...(request.action ? { action: request.action } : {}),
            ...(request.resource === undefined ? {} : { resource: request.resource }),
          }),
        })
      } catch (err) {
        throw protocolError('Resolve request failed', err)
      }
      let text: string
      try { text = await readTextBounded(response, MAX_BODY_BYTES) } catch (err) {
        throw protocolError('read bounded Resolve response', err)
      }
      if (response.status !== 200) {
        logVerifyResult(resolved, KindBot, ENDPOINT, response.status, text)
        throw wireError(response.status, text)
      }
      let wire: WirePrincipal
      try { wire = JSON.parse(text) as WirePrincipal } catch (err) {
        throw protocolError('decode Resolve response', err)
      }
      const actor = readIdentity(wire?.actor, request.spaceId)
      const subject = readIdentity(wire?.subject, request.spaceId)
      if (!actor || !subject || actor.kind !== 'BOT' || wire.mode !== request.mode) {
        throw protocolError('Resolve response identity mismatch')
      }
      if (request.mode === 'AS_BOT') {
        if (subject.kind !== 'BOT' || subject.uid !== actor.uid || wire.delegation !== undefined) {
          throw protocolError('AS_BOT response mismatch')
        }
        return { mode: 'AS_BOT', actor, subject }
      }
      const delegation = wire.delegation
      if (subject.kind !== 'HUMAN' || !delegation || !Number.isSafeInteger(delegation.grant_id) ||
          delegation.grant_id! <= 0 || delegation.matched_scope !== 'ALL' ||
          delegation.action !== request.action || !Number.isSafeInteger(delegation.policy_version) ||
          delegation.policy_version! <= 0 || typeof delegation.decision_id !== 'string' ||
          !DECISION_ID_PATTERN.test(delegation.decision_id)) {
        throw protocolError('OBO response mismatch')
      }
      return {
        mode: 'OBO', actor, subject,
        delegation: {
          grantId: delegation.grant_id!, matchedScope: 'ALL',
          policyVersion: delegation.policy_version!, action: delegation.action!,
          decisionId: delegation.decision_id,
        },
      }
      } catch (err) {
        result = VERIFY_RESULT_INFRA
        if (err instanceof OctoAuthError) {
          resolved.metrics.incErrorByKind(KindBot, err.kind)
          if (err.kind !== 'infra-failure') result = VERIFY_RESULT_AUTH_ERR
        }
        throw err
      } finally {
        resolved.metrics.observeVerifyDuration(KindBot, result, Date.now() - started)
      }
    },
  }
}
