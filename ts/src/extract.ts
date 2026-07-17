/**
 * ExtractCredential helper — pulls the credential from an incoming HTTP
 * request following the shared 5-service pattern: prefer Authorization:
 * Bearer <token>, fall back to the raw "token" header.
 *
 * See design doc §7 and Go SDK's extract.go.
 */

import { OctoAuthError } from './errors.js'
import {
  classifyCredential,
  KindAPIKey,
  KindBot,
  MinAPIKeyLength,
  PrefixApp,
  PrefixBF,
  PrefixUK,
  type Credential,
} from './verifier.js'

export const HeaderAuthorization = 'authorization'
export const HeaderToken = 'token'
export const BearerScheme = 'Bearer'

/**
 * HeadersLike is the minimal request shape extractCredential needs. Both
 * Express's IncomingMessage.headers (Record<string, string | string[] | undefined>)
 * and a plain lowercased map satisfy this.
 */
export interface HeadersLike {
  [name: string]: string | string[] | undefined
}

export interface RequestLike {
  headers: HeadersLike
}

/**
 * extractCredential reads the Authorization: Bearer or "token" header and
 * returns a classified Credential.
 *
 * Throws {@link OctoAuthError} with kind=invalid-credential when no credential
 * is present or classification fails.
 */
export function extractCredential(req: RequestLike): Credential {
  if (req == null || req.headers == null) {
    throw OctoAuthError.invalidCredential('nil request')
  }
  const raw = readCredentialHeader(req.headers)
  if (raw === '') {
    throw OctoAuthError.invalidCredential('missing credential')
  }
  const kind = classifyCredential(raw)
  return { kind, raw }
}

/**
 * readCredentialHeader reads Authorization: Bearer with fallback to "token".
 * Header lookup is case-insensitive; Express lowercases header names but the
 * fallback accommodates arbitrary case for defensive callers.
 */
function readCredentialHeader(h: HeadersLike): string {
  const auth = getHeader(h, HeaderAuthorization)
  if (auth) {
    const token = stripBearer(auth)
    if (token !== '') return token
    // Fall through: an Authorization header without a bearer token is treated
    // the same as no header at all (matches docs-backend behavior).
  }
  const tok = getHeader(h, HeaderToken)
  return tok?.trim() ?? ''
}

/** getHeader looks up name case-insensitively and coerces array values. */
function getHeader(h: HeadersLike, name: string): string | undefined {
  const lower = name.toLowerCase()
  // Fast path: already lowercased (Express, Hono, fetch Headers via .toJSON).
  const direct = h[lower]
  if (direct !== undefined) return coerceHeader(direct)
  // Fall back: scan keys case-insensitively.
  for (const k of Object.keys(h)) {
    if (k.toLowerCase() === lower) {
      return coerceHeader(h[k])
    }
  }
  return undefined
}

function coerceHeader(v: string | string[] | undefined): string | undefined {
  if (v === undefined) return undefined
  if (Array.isArray(v)) return v[0]
  return v
}

/**
 * stripBearer returns the token part of "Bearer <token>" (scheme match is
 * case-insensitive per RFC 7235). Returns "" if value is not a bearer credential.
 */
function stripBearer(v: string): string {
  const trimmed = v.trim()
  if (trimmed.length <= BearerScheme.length) return ''
  if (trimmed.slice(0, BearerScheme.length).toLowerCase() !== BearerScheme.toLowerCase()) {
    return ''
  }
  const rest = trimmed.slice(BearerScheme.length)
  if (rest.length === 0 || (rest[0] !== ' ' && rest[0] !== '\t')) return ''
  return rest.trim()
}

/**
 * validateAPIKey checks that token has the "uk_" prefix and meets the length
 * requirement. Useful for producers minting their own keys.
 */
export function validateAPIKey(token: string): void {
  if (!token.startsWith(PrefixUK)) {
    throw OctoAuthError.invalidCredential('api key missing uk_ prefix', {
      verifier: KindAPIKey,
    })
  }
  if (token.length < MinAPIKeyLength) {
    throw OctoAuthError.invalidCredential('api key too short', {
      verifier: KindAPIKey,
    })
  }
}

/** validateBotToken checks that token has one of the bot-realm prefixes. */
export function validateBotToken(token: string): void {
  if (token.startsWith(PrefixBF) || token.startsWith(PrefixApp)) {
    if (token.length <= PrefixBF.length) {
      throw OctoAuthError.invalidCredential('bot token has prefix only', {
        verifier: KindBot,
      })
    }
    return
  }
  throw OctoAuthError.invalidCredential('bot token missing bf_/app_ prefix', {
    verifier: KindBot,
  })
}
