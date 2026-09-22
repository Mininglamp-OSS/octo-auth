/**
 * Typed errors for the SDK.
 *
 * See design doc §5 and Go SDK's errors.go. TS uses a class-based error with a
 * discriminant `kind` field instead of Go's typed-int + sentinel pattern.
 * Callers do `err instanceof OctoAuthError && err.kind === 'invalid-credential'`
 * to switch on kinds; sentinel factories help keep call sites terse.
 */

import type { PrincipalKind } from './verifier.js'

/** ErrorKind classifies an SDK error into stable buckets. */
export type ErrorKind =
  | 'invalid-credential'
  | 'disabled'
  | 'infra-failure'
  | 'pre-v2-server'
  | 'forbidden'
  | 'invalid-request'

/** Options passed to the OctoAuthError constructor. */
export interface OctoAuthErrorOptions {
  cause?: unknown
  verifier?: PrincipalKind
  code?: string
  requestId?: string
}

/**
 * OctoAuthError is the typed error thrown by every SDK entry point. Callers
 * should compare against `err.kind` rather than by identity so verifier
 * implementations can construct fresh values with populated message / cause /
 * verifier fields.
 *
 * Note: `pre-v2-server` is an internal signal handled inside verifiers
 * (surfaced via `PrincipalContext.kind = 'unknown-server'`) and should not
 * reach callers.
 */
export class OctoAuthError extends Error {
  /** The coarse-grained bucket. */
  readonly kind: ErrorKind
  /** Which realm produced the error, when known. */
  readonly verifier?: PrincipalKind
  readonly code?: string
  readonly requestId?: string

  constructor(
    kind: ErrorKind,
    message?: string,
    opts?: OctoAuthErrorOptions,
  ) {
    // Native Error.cause support via ErrorOptions.
    super(message ?? kind, { cause: opts?.cause })
    this.name = 'OctoAuthError'
    this.kind = kind
    if (opts?.verifier !== undefined) {
      this.verifier = opts.verifier
    }
    if (opts?.code !== undefined) this.code = opts.code
    if (opts?.requestId !== undefined) this.requestId = opts.requestId
    // Ensure prototype chain works across ES targets.
    Object.setPrototypeOf(this, new.target.prototype)
  }

  /** Sentinel factory: invalid-credential. */
  static invalidCredential(
    message?: string,
    opts?: OctoAuthErrorOptions,
  ): OctoAuthError {
    return new OctoAuthError('invalid-credential', message, opts)
  }
  /** Sentinel factory: disabled. */
  static disabled(
    message?: string,
    opts?: OctoAuthErrorOptions,
  ): OctoAuthError {
    return new OctoAuthError('disabled', message, opts)
  }
  /** Sentinel factory: infra-failure. */
  static infraFailure(
    message?: string,
    opts?: OctoAuthErrorOptions,
  ): OctoAuthError {
    return new OctoAuthError('infra-failure', message, opts)
  }
  /** Sentinel factory: forbidden. */
  static forbidden(
    message?: string,
    opts?: OctoAuthErrorOptions,
  ): OctoAuthError {
    return new OctoAuthError('forbidden', message, opts)
  }
}

/**
 * Response bodies emitted by defaultErrorMapper. They are deliberately
 * enumeration-resistant: two failure modes mapping to the same status produce
 * byte-identical output so an attacker cannot infer whether a token is unknown
 * vs expired vs malformed. See design doc §5.2 and R-P1-6.
 *
 * The byte-identical rule matters — matching Go SDK's DefaultErrorMapper
 * (config.go bodyUnauthorized) exactly.
 */
export const BODY_UNAUTHORIZED = '{"error":"unauthorized"}'
export const BODY_DISABLED = '{"error":"disabled"}'
export const BODY_UPSTREAM_UNAVAILABLE = '{"error":"upstream_unavailable"}'
export const BODY_FORBIDDEN = '{"error":"forbidden"}'
export const BODY_INVALID_REQUEST = '{"error":"invalid_request"}'
export const BODY_INTERNAL = '{"error":"internal"}'

/**
 * ErrorMapperResult is what an ErrorMapperFn returns — an HTTP status + body
 * pair the middleware writes verbatim to the response.
 */
export interface ErrorMapperResult {
  status: number
  body: string
}

/** ErrorMapperFn converts an SDK error into an HTTP response tuple. */
export type ErrorMapperFn = (err: unknown) => ErrorMapperResult

/**
 * defaultErrorMapper is the reference status / body table:
 *
 *   invalid-credential → 401 {"error":"unauthorized"}
 *   disabled           → 403 {"error":"disabled"}
 *   infra-failure      → 503 {"error":"upstream_unavailable"}
 *   forbidden          → 403 {"error":"forbidden"}
 *   invalid-request    → 400 {"error":"invalid_request"}
 *   otherwise          → 500 {"error":"internal"}
 *
 * Non-OctoAuthError values and pre-v2-server signals fall through to 500.
 */
export const defaultErrorMapper: ErrorMapperFn = (err: unknown) => {
  if (!(err instanceof OctoAuthError)) {
    return { status: 500, body: BODY_INTERNAL }
  }
  switch (err.kind) {
    case 'invalid-credential':
      return { status: 401, body: BODY_UNAUTHORIZED }
    case 'disabled':
      return { status: 403, body: BODY_DISABLED }
    case 'infra-failure':
      return { status: 503, body: BODY_UPSTREAM_UNAVAILABLE }
    case 'forbidden':
      return { status: 403, body: BODY_FORBIDDEN }
    case 'invalid-request':
      return { status: 400, body: BODY_INVALID_REQUEST }
    default:
      return { status: 500, body: BODY_INTERNAL }
  }
}
