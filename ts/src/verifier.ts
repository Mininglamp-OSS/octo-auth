/**
 * Verifier interface, Principal type, and MultiVerifier facade.
 *
 * See design doc §2 / §3 and Go SDK's verifier.go for the reference behavior.
 * TS keeps parity with Go semantics: `classifyCredential` mirrors Go's dispatch
 * rules exactly (empty → invalid; uk_ + len>=35 → apikey; bf_ / app_ → bot;
 * else → session).
 */

import { OctoAuthError } from './errors.js'

/** PrincipalKind identifies which authentication realm produced a Principal. */
export type PrincipalKind = 'session' | 'bot' | 'apikey'

/** Session realm (32-hex UUID token, no prefix). */
export const KindSession: PrincipalKind = 'session'
/** Bot realm (bf_-prefixed; app_ reserved). */
export const KindBot: PrincipalKind = 'bot'
/** User API key realm (uk_-prefixed, length >= 35). */
export const KindAPIKey: PrincipalKind = 'apikey'

/**
 * ContextKind describes the state of the include=context payload for a Principal.
 * Callers should switch on this value rather than testing spaces for undefined,
 * because an empty array is a legitimate v2+ response.
 *
 * States:
 * - `'not-requested'`: The verifier did not request include=context (e.g. bot
 *   realm, or session/apikey realm with `requestIncludeContext=false`). Nothing
 *   to interpret; `spaces` / `ownedBotsBySpace` are undefined by design.
 * - `'included'`: Server returned `context_included=true`; `spaces` /
 *   `ownedBotsBySpace` are authoritative (an empty `spaces` array is a
 *   legitimate v2+ response for a user with zero memberships).
 * - `'not-included'`: Server explicitly returned `context_included=false`.
 *   Currently unreachable against server v3 (server-side omitempty on
 *   `context_included` erases explicit false on the wire). Preserved for a
 *   future server that drops omitempty; callers SHOULD NOT rely on this state
 *   being observed today.
 * - `'unknown-server'`: Response omitted `context_included`. Ambiguous by
 *   design: the server is either pre-v2 (never emits the field) OR v3+ that
 *   declined this call (omitempty erased explicit false). Callers MUST
 *   fail-closed and MUST NOT infer authorisation from `spaces` /
 *   `ownedBotsBySpace` on the same response.
 */
export type ContextKind =
  | 'not-requested'
  | 'included'
  | 'not-included'
  | 'unknown-server'

/**
 * PrincipalContext carries the optional include=context payload from
 * octo-server v2+.
 */
export interface PrincipalContext {
  kind: ContextKind
  spaces?: readonly string[]
  ownedBotsBySpace?: Readonly<Record<string, readonly string[]>>
}

/**
 * Principal is the resolved identity returned by a Verifier.
 *
 * Field population depends on `kind`:
 *   - session: uid, name, role, relatedUids (self + owned bots); spaceId
 *     requires X-Space-Id enrichment at the middleware layer.
 *   - bot:     uid, name, role, spaceId, ownerUid, ownerName, relatedUids=[self].
 *   - apikey:  uid, spaceId; name/role empty, relatedUids undefined.
 */
export interface Principal {
  kind: PrincipalKind
  uid: string
  name?: string
  role?: string
  spaceId?: string
  ownerUid?: string
  ownerName?: string
  relatedUids?: readonly string[]
  context: PrincipalContext
}

/** Credential is the extracted raw credential plus its inferred kind. */
export interface Credential {
  kind: PrincipalKind
  raw: string
}

/** Options threaded through Verifier.verify (currently only AbortSignal). */
export interface VerifyOptions {
  signal?: AbortSignal
}

/**
 * Verifier resolves a raw credential into a Principal. Implementations must be
 * safe for concurrent use.
 */
export interface Verifier {
  readonly kind: PrincipalKind
  verify(credential: string, opts?: VerifyOptions): Promise<Principal>
}

/**
 * MultiVerifier is a facade Verifier that dispatches to a per-kind child
 * verifier based on the credential prefix.
 */
export interface MultiVerifier extends Verifier {
  register(v: Verifier): MultiVerifier
}

/** Credential prefix constants. See Go SDK extract.go for parity. */
export const PrefixUK = 'uk_'
export const PrefixBF = 'bf_'
export const PrefixApp = 'app_'
/** Minimum total length (including "uk_") a user API key must have. */
export const MinAPIKeyLength = 35

/**
 * classifyCredential applies the design-doc §3 dispatch rules. Used by both
 * MultiVerifier and extractCredential so the two stay in lock-step.
 *
 * Throws {@link OctoAuthError} with kind=invalid-credential when the input is
 * empty or is a too-short uk_ key.
 */
export function classifyCredential(credential: string): PrincipalKind {
  if (credential === '') {
    throw new OctoAuthError('invalid-credential', 'empty credential')
  }
  if (credential.startsWith(PrefixUK)) {
    if (credential.length < MinAPIKeyLength) {
      throw new OctoAuthError('invalid-credential', 'api key too short', {
        verifier: KindAPIKey,
      })
    }
    return KindAPIKey
  }
  if (credential.startsWith(PrefixBF)) {
    return KindBot
  }
  if (credential.startsWith(PrefixApp)) {
    // Reserved for App Bot tokens; SDK v1 forwards to bot verifier so future
    // additions stay additive.
    return KindBot
  }
  return KindSession
}

/**
 * newMultiVerifier builds a MultiVerifier populated with the given child
 * verifiers. If two verifiers share a kind, the later one wins.
 *
 * A dispatch to a realm with no registered child verifier returns an
 * invalid-credential error naming the missing realm.
 */
export function newMultiVerifier(...verifiers: Verifier[]): MultiVerifier {
  const children = new Map<PrincipalKind, Verifier>()
  for (const v of verifiers) {
    if (v == null) continue
    children.set(v.kind, v)
  }
  const facade: MultiVerifier = {
    // Facade kind is deliberately not a real realm; callers should inspect
    // Principal.kind on the returned value instead.
    kind: 'multi' as PrincipalKind,
    register(v: Verifier): MultiVerifier {
      if (v != null) children.set(v.kind, v)
      return facade
    },
    async verify(credential: string, opts?: VerifyOptions): Promise<Principal> {
      const k = classifyCredential(credential)
      const child = children.get(k)
      if (!child) {
        throw new OctoAuthError(
          'invalid-credential',
          `no verifier registered for kind "${k}"`,
          { verifier: k },
        )
      }
      return child.verify(credential, opts)
    },
  }
  return facade
}
