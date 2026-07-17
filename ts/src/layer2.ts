/**
 * Layer-2 short-lived JWTs used by hocuspocus-style long-lived connections.
 *
 * See design doc §10 and Go SDK's layer2/layer2.go. v1 supports HS256 only;
 * EdDSA is a documented v1.1 gap and returns unsupported-algorithm at both
 * issue and verify time.
 *
 * TS uses `jose` (per R-TS-5) rather than `jsonwebtoken`. jose's
 * jwtVerify() is passed `algorithms: ['HS256']` explicitly to defend against
 * alg-confusion attacks; jose automatically rejects `alg: none`.
 */

import { SignJWT, jwtVerify, errors as joseErrors } from 'jose'
import { OctoAuthError } from './errors.js'

/** DefaultTTLSeconds matches docs-backend's COLLAB_TOKEN_TTL_SECONDS default. */
export const DEFAULT_TTL_SECONDS = 300
/** MinHS256KeySize is the minimum acceptable HS256 secret length in bytes. */
export const MIN_HS256_KEY_SIZE = 32

/** Supported signature algorithms. */
export type SigAlg = 'HS256' | 'EdDSA'
export const AlgHS256: SigAlg = 'HS256'
/** AlgEdDSA is accepted as a valid string but returns unsupported-algorithm at issue/verify time. */
export const AlgEdDSA: SigAlg = 'EdDSA'

/**
 * ShortLivedClaims is the payload placed into a layer-2 JWT. `exp` is Unix
 * seconds and is derived from IssueOptions.ttlSeconds at issue time.
 */
export interface ShortLivedClaims {
  uid: string
  documentName: string
  role: string
  permissionEpoch: number
  /** Unix seconds. Populated by verifyShortLivedToken; ignored by issue. */
  exp: number
}

/** IssueOptions configures a call to issueShortLivedToken. */
export interface IssueOptions {
  claims: Omit<ShortLivedClaims, 'exp'>
  /** TTL in seconds. Defaults to 300 (5 minutes). */
  ttlSeconds?: number
  /** Signing key bytes. Must be >= 32 bytes for HS256. */
  sigKey: Uint8Array
  sigAlg: SigAlg
}

/** VerifyOptions configures a call to verifyShortLivedToken. */
export interface VerifyOptions {
  sigKey: Uint8Array
  sigAlg: SigAlg
}

/**
 * issueShortLivedToken signs a JWT containing opts.claims and returns the
 * compact serialization. The exp claim is set to now + opts.ttlSeconds.
 *
 * Throws OctoAuthError with kinds:
 *   - invalid-credential: missing uid, missing/short sigKey
 *   - infra-failure:      signing error
 * or for EdDSA / unknown algs, unsupported-algorithm (OctoAuthError with a
 * kind not in the standard 5 — see below).
 *
 * Since our ErrorKind union doesn't include an "unsupported-algorithm"
 * literal, layer2 uses `infra-failure` for these and surfaces the reason via
 * the error message. Callers can `instanceof OctoAuthError` and inspect
 * `.message` for granular handling — matches Go's ErrUnsupportedAlgorithm
 * approach (a distinct sentinel, not an ErrorKind).
 */
export async function issueShortLivedToken(opts: IssueOptions): Promise<string> {
  if (!opts.claims || !opts.claims.uid) {
    throw new OctoAuthError('invalid-credential', 'layer2: claims missing required uid')
  }
  if (!opts.sigKey || opts.sigKey.length === 0) {
    throw new OctoAuthError('invalid-credential', 'layer2: sigKey is required')
  }
  const ttl = opts.ttlSeconds && opts.ttlSeconds > 0
    ? opts.ttlSeconds
    : DEFAULT_TTL_SECONDS
  if (opts.sigAlg === AlgHS256) {
    if (opts.sigKey.length < MIN_HS256_KEY_SIZE) {
      throw new OctoAuthError(
        'invalid-credential',
        `layer2: HS256 secret must be at least ${MIN_HS256_KEY_SIZE} bytes`,
      )
    }
  } else if (opts.sigAlg === AlgEdDSA) {
    throw new OctoAuthError(
      'infra-failure',
      'layer2: unsupported signature algorithm (v1 supports HS256 only): "EdDSA"',
    )
  } else {
    throw new OctoAuthError(
      'infra-failure',
      `layer2: unsupported signature algorithm (v1 supports HS256 only): "${String(opts.sigAlg)}"`,
    )
  }
  const nowSec = Math.floor(Date.now() / 1000)
  const expSec = nowSec + ttl
  try {
    const jwt = await new SignJWT({
      uid: opts.claims.uid,
      document_name: opts.claims.documentName,
      role: opts.claims.role,
      permission_epoch: opts.claims.permissionEpoch,
    })
      .setProtectedHeader({ alg: AlgHS256 })
      .setIssuedAt(nowSec)
      .setExpirationTime(expSec)
      .sign(opts.sigKey)
    return jwt
  } catch (err) {
    throw new OctoAuthError('infra-failure', 'layer2: sign failed', {
      cause: err,
    })
  }
}

/**
 * verifyShortLivedToken parses tokenStr, verifies the signature and
 * expiration, and returns the reconstituted claims.
 *
 * Throws OctoAuthError:
 *   - invalid-credential: missing sigKey / expired / tampered / bad shape
 *   - infra-failure:      unsupported algorithm
 */
export async function verifyShortLivedToken(
  tokenStr: string,
  opts: VerifyOptions,
): Promise<ShortLivedClaims> {
  if (!opts.sigKey || opts.sigKey.length === 0) {
    throw new OctoAuthError('invalid-credential', 'layer2: sigKey is required')
  }
  if (opts.sigAlg === AlgEdDSA) {
    throw new OctoAuthError(
      'infra-failure',
      'layer2: unsupported signature algorithm (v1 supports HS256 only): "EdDSA"',
    )
  }
  if (opts.sigAlg !== AlgHS256) {
    throw new OctoAuthError(
      'infra-failure',
      `layer2: unsupported signature algorithm (v1 supports HS256 only): "${String(opts.sigAlg)}"`,
    )
  }
  let payload: Record<string, unknown>
  try {
    // Alg-confusion defense: only HS256 is accepted; jose also rejects
    // alg: none automatically.
    const result = await jwtVerify(tokenStr, opts.sigKey, {
      algorithms: [AlgHS256],
    })
    payload = result.payload as Record<string, unknown>
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) {
      throw new OctoAuthError('invalid-credential', 'layer2: token expired', {
        cause: err,
      })
    }
    throw new OctoAuthError('invalid-credential', 'layer2: token invalid', {
      cause: err,
    })
  }
  const uid = typeof payload['uid'] === 'string' ? payload['uid'] : ''
  if (uid === '') {
    throw new OctoAuthError('invalid-credential', 'layer2: token invalid: missing uid')
  }
  const documentName =
    typeof payload['document_name'] === 'string'
      ? (payload['document_name'] as string)
      : ''
  const role = typeof payload['role'] === 'string' ? (payload['role'] as string) : ''
  const permissionEpoch = numericClaim(payload['permission_epoch'])
  const exp = numericClaim(payload['exp'])
  return {
    uid,
    documentName,
    role,
    permissionEpoch,
    exp,
  }
}

function numericClaim(v: unknown): number {
  if (typeof v === 'number') return v
  if (typeof v === 'string' && v !== '') {
    const n = Number(v)
    return Number.isFinite(n) ? n : 0
  }
  return 0
}
