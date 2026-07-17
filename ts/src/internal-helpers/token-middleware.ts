/**
 * internal-helpers/token-middleware — X-*-Token consumer middleware.
 *
 * Uses Node's `crypto.timingSafeEqual` for constant-time comparison. Because
 * `timingSafeEqual` throws RangeError when the two buffers have different
 * lengths, we manually handle the length-mismatch case by still comparing
 * against a same-length junk buffer — that preserves constant-time semantics
 * even for probes of the wrong length.
 *
 * Env-var check runs at factory construction time; missing / empty throws
 * synchronously so misconfiguration fails at server startup.
 */

import { timingSafeEqual } from 'node:crypto'
import { Buffer } from 'node:buffer'
import type { Logger } from '../config.js'
import { consoleLogger } from '../config.js'
import { maskToken } from './notify-client.js'

/** InternalTokenConfig configures the internal-token middleware factories. */
export interface InternalTokenConfig {
  /**
   * Required. Request header that carries the shared secret, e.g.
   * "X-Runtime-Admin-Token" (fleet) or "X-Internal-Token" (server).
   */
  headerName: string
  /** Required. Process env var with the expected value. */
  tokenEnvVar: string
  /** Logger. Defaults to consoleLogger. */
  logger?: Logger
}

/** Byte-identical body used on reject — matches Go internalTokenUnauthorizedBody. */
export const INTERNAL_TOKEN_UNAUTHORIZED_BODY = '{"error":"unauthorized"}'

interface Resolved {
  headerName: string
  headerNameLower: string
  tokenBuffer: Buffer
  tokenHint: string
  logger: Logger
}

function resolveInternalTokenConfig(
  cfg: InternalTokenConfig,
  source: string,
): Resolved {
  if (!cfg.headerName) {
    throw new Error(`${source}: InternalTokenConfig.headerName is required`)
  }
  if (!cfg.tokenEnvVar) {
    throw new Error(`${source}: InternalTokenConfig.tokenEnvVar is required`)
  }
  const token = process.env[cfg.tokenEnvVar]
  if (!token) {
    throw new Error(
      `${source}: env var "${cfg.tokenEnvVar}" is empty (fail-closed)`,
    )
  }
  return {
    headerName: cfg.headerName,
    headerNameLower: cfg.headerName.toLowerCase(),
    tokenBuffer: Buffer.from(token, 'utf8'),
    tokenHint: maskToken(token),
    logger: cfg.logger ?? consoleLogger,
  }
}

/**
 * constantTimeEqualString compares got (untrusted, arbitrary length) with
 * wantBuf (trusted secret bytes) in constant time relative to want's length.
 *
 * Node's timingSafeEqual throws on unequal lengths, which would itself leak
 * the secret length. We work around it by comparing against a same-length
 * junk buffer when lengths differ, still burning O(len(want)) time so an
 * attacker cannot use timing to distinguish "wrong length" from "wrong
 * content".
 */
function constantTimeEqualString(got: string, wantBuf: Buffer): boolean {
  if (got.length === 0) return false
  const gotBuf = Buffer.from(got, 'utf8')
  if (gotBuf.length !== wantBuf.length) {
    // Burn ~O(len(want)) time before returning false.
    const junk = Buffer.alloc(wantBuf.length)
    try {
      timingSafeEqual(junk, wantBuf)
    } catch {
      // Impossible: junk and wantBuf are same length.
    }
    return false
  }
  return timingSafeEqual(gotBuf, wantBuf)
}

/**
 * Minimal express-compatible RequestHandler shape. We deliberately do NOT
 * import from `express` to keep it a peer-only dependency. Callers who use
 * this from an express app will find the shape assignable.
 */
export interface MinimalExpressRequest {
  headers: Record<string, string | string[] | undefined>
}

/** MinimalExpressResponse — just what token-middleware writes on reject. */
export interface MinimalExpressResponse {
  status(code: number): MinimalExpressResponse
  setHeader(name: string, value: string): void
  send(body: string): void
  end(): void
}

export type MinimalExpressNext = (err?: unknown) => void

export type MinimalExpressHandler = (
  req: MinimalExpressRequest,
  res: MinimalExpressResponse,
  next: MinimalExpressNext,
) => void

/**
 * expressInternalTokenMiddleware returns an express-compatible middleware
 * that validates the configured header against the environment-provided
 * shared secret using constant-time comparison. Failed checks respond with
 * 401 and a byte-identical body regardless of whether the header was
 * missing, empty, or wrong.
 *
 * Throws at factory-construction time if cfg is misconfigured.
 */
export function expressInternalTokenMiddleware(
  cfg: InternalTokenConfig,
): MinimalExpressHandler {
  const r = resolveInternalTokenConfig(
    cfg,
    'octoauth/internal-helpers.expressInternalTokenMiddleware',
  )
  return (req, res, next) => {
    const got = readSingleHeader(req.headers, r.headerNameLower)
    if (!constantTimeEqualString(got, r.tokenBuffer)) {
      r.logger.debug('octoauth/internal-helpers: internal token check failed', {
        header: r.headerName,
        token_hint: r.tokenHint,
        header_present: got !== '',
      })
      res.status(401)
      res.setHeader('Content-Type', 'application/json')
      res.send(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
      return
    }
    next()
  }
}

/**
 * Generic (non-express) node:http middleware wrapper. Given a `next()` handler
 * (req, res) => void, returns a wrapper that performs the same token check
 * and short-circuits with a 401 on failure.
 *
 * The `res` object needs `writeHead(status, headers)` + `end(body)` — the
 * minimum node:http contract.
 */
export interface MinimalNodeReq {
  headers: Record<string, string | string[] | undefined>
}

export interface MinimalNodeRes {
  writeHead(status: number, headers?: Record<string, string>): unknown
  end(chunk?: string): void
}

export type NodeHandler = (req: MinimalNodeReq, res: MinimalNodeRes) => void

export function wrapNodeInternalTokenMiddleware(
  cfg: InternalTokenConfig,
  next: NodeHandler,
): NodeHandler {
  if (typeof next !== 'function') {
    throw new Error(
      'octoauth/internal-helpers.wrapNodeInternalTokenMiddleware: next handler is required',
    )
  }
  const r = resolveInternalTokenConfig(
    cfg,
    'octoauth/internal-helpers.wrapNodeInternalTokenMiddleware',
  )
  return (req, res) => {
    const got = readSingleHeader(req.headers, r.headerNameLower)
    if (!constantTimeEqualString(got, r.tokenBuffer)) {
      r.logger.debug('octoauth/internal-helpers: internal token check failed', {
        header: r.headerName,
        token_hint: r.tokenHint,
        header_present: got !== '',
      })
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end(INTERNAL_TOKEN_UNAUTHORIZED_BODY)
      return
    }
    next(req, res)
  }
}

function readSingleHeader(
  headers: Record<string, string | string[] | undefined>,
  nameLower: string,
): string {
  const direct = headers[nameLower]
  if (direct !== undefined) return coerce(direct)
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === nameLower) return coerce(headers[k])
  }
  return ''
}

function coerce(v: string | string[] | undefined): string {
  if (v === undefined) return ''
  if (Array.isArray(v)) return v[0] ?? ''
  return v
}
