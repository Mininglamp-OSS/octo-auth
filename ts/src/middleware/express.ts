/**
 * Express middleware factory.
 *
 * See design doc §8.2 and Go SDK's middleware/gin/gin.go for the reference
 * flow: extract → optional requireKind check → verify → clone → enrich
 * space header → attach req.principal → next.
 *
 * The peer dependency on `express` is left runtime-only via a minimal shape
 * — we don't import from `express` so this file compiles even when the peer
 * is not installed. Callers with express installed will find our shape
 * assignable to express.RequestHandler.
 */

import { OctoAuthError, defaultErrorMapper } from '../errors.js'
import type { ErrorMapperFn } from '../errors.js'
import type { Principal, PrincipalKind, Verifier } from '../verifier.js'
import { KindBot, KindSession } from '../verifier.js'
import type { BotResolver, BotResolveMode, ResolvedPrincipal } from '../resolver.js'
import { clonePrincipal } from '../principal-clone.js'
import { extractCredential } from '../extract.js'
import type { Credential } from '../verifier.js'

/**
 * MinimalExpressRequest is the subset of express.Request we need. Express's
 * `Request` extends `IncomingMessage` whose `.headers` matches this shape.
 * We attach the resolved principal to `.principal` — the ambient type
 * declaration in `src/types-ext.d.ts` makes this typed on real express
 * requests too.
 */
export interface MinimalExpressRequest {
  headers: Record<string, string | string[] | undefined>
  query?: Record<string, unknown>
  /** Populated by this middleware on success. */
  principal?: Principal
  /** Populated by this middleware on success. */
  credential?: Credential
  /** Populated by expressBotResolveMiddleware on success. */
  resolvedPrincipal?: ResolvedPrincipal
}

/** Fixed route policy for the new Bot-only Resolve middleware. */
export interface ExpressBotResolveOptions {
  resolver: BotResolver
  mode: BotResolveMode
  action?: string
  /** Defaults to the explicit `space_id` query parameter. */
  spaceId?: (req: MinimalExpressRequest) => string
  errorMapper?: ErrorMapperFn
}

/**
 * Resolve Bot identity for a controlled route. The Action is fixed at
 * construction time, never read from caller input. An OBO route requires
 * `obo=true` and refuses to fall back to AS_BOT on any denial.
 */
export function expressBotResolveMiddleware(opts: ExpressBotResolveOptions): MinimalExpressHandler {
  if (!opts?.resolver || (opts.mode !== 'OBO' && opts.mode !== 'AS_BOT') ||
      (opts.mode === 'OBO') !== Boolean(opts.action)) {
    throw new Error('octoauth/middleware/express: Resolver, mode, and fixed OBO Action are required')
  }
  const mapper = opts.errorMapper ?? defaultErrorMapper
  const spaceId = opts.spaceId ?? ((req: MinimalExpressRequest) => {
    const value = req.query?.space_id
    return typeof value === 'string' ? value : ''
  })
  return async (req, res, next) => {
    try {
      const credential = extractCredential(req)
      if (credential.kind !== KindBot) {
        throw new OctoAuthError('invalid-credential', 'Bot credential required', { verifier: KindBot })
      }
      const marker = req.query?.obo
      if ((opts.mode === 'OBO' && marker !== 'true') ||
          (opts.mode === 'AS_BOT' && marker !== undefined)) {
        throw new OctoAuthError('invalid-request', 'OBO marker does not match route mode', { verifier: KindBot })
      }
      for (const forbidden of ['on_behalf_of', 'human_uid', 'subject_uid']) {
        if (Object.prototype.hasOwnProperty.call(req.query ?? {}, forbidden)) {
          throw new OctoAuthError('invalid-request', 'Subject cannot be selected by caller', { verifier: KindBot })
        }
      }
      req.resolvedPrincipal = await opts.resolver.resolve(credential.raw, {
        mode: opts.mode, spaceId: spaceId(req),
        ...(opts.mode === 'OBO' ? { action: opts.action } : {}),
      })
      next()
    } catch (err) {
      abort(res, mapper, err)
    }
  }
}

export interface MinimalExpressResponse {
  status(code: number): MinimalExpressResponse
  setHeader(name: string, value: string): void
  send(body: string): void
}

export type MinimalExpressNext = (err?: unknown) => void

export type MinimalExpressHandler = (
  req: MinimalExpressRequest,
  res: MinimalExpressResponse,
  next: MinimalExpressNext,
) => void | Promise<void>

/** ExpressMiddlewareOptions matches design doc §8.2. */
export interface ExpressMiddlewareOptions {
  /** Required. Single verifier or MultiVerifier. */
  verifier: Verifier
  /** Optional. When set, credentials of other kinds are rejected with forbidden. */
  requireKind?: PrincipalKind
  /** Optional. Name of the session-realm X-Space-Id fallback header. */
  spaceHeader?: string
  /** Optional. Replaces defaultErrorMapper. */
  errorMapper?: ErrorMapperFn
}

/**
 * expressMiddleware builds an express-compatible middleware.
 *
 * On success attaches `req.principal` and `req.credential` before calling
 * `next()`. On failure writes the mapped status/body and returns without
 * calling `next()`.
 *
 * Throws synchronously (during factory call) if `opts.verifier` is missing.
 */
export function expressMiddleware(
  opts: ExpressMiddlewareOptions,
): MinimalExpressHandler {
  if (!opts || !opts.verifier) {
    throw new Error(
      'octoauth/middleware/express: Options.verifier is required',
    )
  }
  const mapper = opts.errorMapper ?? defaultErrorMapper
  return async (req, res, next) => {
    try {
      const cred = extractCredential(req)
      if (opts.requireKind && cred.kind !== opts.requireKind) {
        throw new OctoAuthError('forbidden', 'credential kind not permitted', {
          verifier: cred.kind,
        })
      }
      const rawPrincipal = await opts.verifier.verify(cred.raw)
      // Defensive clone before mutation so the cache-shared *Principal is
      // never modified in place.
      const principal = clonePrincipal(rawPrincipal)
      if (principal.kind === KindSession && opts.spaceHeader) {
        enrichSpaceFromHeader(req, principal, opts.spaceHeader)
      }
      req.principal = principal
      req.credential = cred
      next()
    } catch (err) {
      abort(res, mapper, err)
    }
  }
}

/**
 * enrichSpaceFromHeader applies the design-doc §8.1 rules for session-realm
 * X-Space-Id enrichment. Matches Go's middleware/internal/enrich/enrich.go.
 *
 *   - included: sid MUST be in principal.context.spaces → else forbidden
 *   - not-included / unknown-server: fail-closed — the SDK refuses to bind
 *     an unverified client-supplied space id, matching the wire contract
 *     (contract/auth-v1.yaml §fail-closed rules). Reachable on default path
 *     when a v3 server omits context_included via omitempty.
 *   - not-requested: no-op (defensive)
 */
function enrichSpaceFromHeader(
  req: MinimalExpressRequest,
  principal: Principal,
  headerName: string,
): void {
  const sid = readSid(req.headers, headerName)
  if (sid === '') return
  switch (principal.context.kind) {
    case 'included': {
      const spaces = principal.context.spaces ?? []
      if (!spaces.includes(sid)) {
        throw new OctoAuthError(
          'forbidden',
          "requested space is not in principal's authorized set",
          { verifier: KindSession },
        )
      }
      principal.spaceId = sid
      return
    }
    case 'not-included':
    case 'unknown-server':
      throw new OctoAuthError(
        'forbidden',
        "requested space is not in principal's authorized set",
        { verifier: KindSession },
      )
    case 'not-requested':
      return
  }
}

function readSid(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string {
  const lower = name.toLowerCase()
  const direct = headers[lower]
  if (direct !== undefined) return coerce(direct)
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === lower) return coerce(headers[k])
  }
  return ''
}

function coerce(v: string | string[] | undefined): string {
  if (v === undefined) return ''
  if (Array.isArray(v)) return v[0] ?? ''
  return v
}

function abort(
  res: MinimalExpressResponse,
  mapper: ErrorMapperFn,
  err: unknown,
): void {
  const { status, body } = mapper(err)
  res.status(status)
  res.setHeader('Content-Type', 'application/json')
  res.send(body)
}
