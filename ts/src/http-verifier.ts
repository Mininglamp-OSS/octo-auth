/**
 * Internal shared HTTP helper used by the three verifier implementations.
 * Not exported from index.ts; verifier implementations import it via relative
 * path.
 *
 * Status mapping:
 *   2xx → success (body returned)
 *   401 → invalid-credential
 *   403 → disabled
 *   other 4xx/5xx → infra-failure
 *   transport / decode / abort errors → infra-failure
 *
 * Server-side response bodies are never surfaced in error messages (that would
 * leak enumeration signals through the reverse proxy). They are logged at
 * debug level with a 200-byte cap.
 */

import { OctoAuthError } from './errors.js'
import { hashCacheKey } from './cache.js'
import { clonePrincipal } from './principal-clone.js'
import type { ResolvedConfig } from './config.js'
import type { Principal, PrincipalKind } from './verifier.js'

export const VERIFY_RESULT_HIT = 'hit'
export const VERIFY_RESULT_MISS_OK = 'miss-ok'
export const VERIFY_RESULT_AUTH_ERR = 'miss-err'
export const VERIFY_RESULT_INFRA = 'error'

const MAX_LOGGED_BODY_BYTES = 200

/**
 * doVerifyRequest builds and executes a JSON-body POST against
 * cfg.baseUrl + endpoint. On success returns the parsed JSON body; on failure
 * throws a typed OctoAuthError.
 *
 * `endpoint` may include a query string, e.g. "/v1/auth/verify?include=context".
 */
export async function doVerifyRequest(
  cfg: ResolvedConfig,
  endpoint: string,
  reqBody: unknown,
  verifier: PrincipalKind,
  signal?: AbortSignal,
): Promise<unknown> {
  const url = cfg.baseUrl + endpoint
  let payload: string
  try {
    payload = JSON.stringify(reqBody)
  } catch (err) {
    throw new OctoAuthError('infra-failure', 'encode verify request body', {
      cause: err,
      verifier,
    })
  }

  // Compose our timeout signal with the caller-supplied one via
  // AbortSignal.any (Node 20+); an aborted composite aborts the fetch.
  const timeoutCtl = new AbortController()
  const timer = setTimeout(() => timeoutCtl.abort(), cfg.timeoutMs)
  const composite = signal
    ? AbortSignal.any([signal, timeoutCtl.signal])
    : timeoutCtl.signal

  let resp: Response
  try {
    resp = await cfg.fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: payload,
      signal: composite,
    })
  } catch (err) {
    // AbortError / TypeError from fetch / DNS failures — all bucket into infra.
    throw new OctoAuthError('infra-failure', 'verify request failed', {
      cause: err,
      verifier,
    })
  } finally {
    clearTimeout(timer)
  }

  let bodyText: string
  try {
    bodyText = await resp.text()
  } catch (err) {
    throw new OctoAuthError('infra-failure', 'read verify response body', {
      cause: err,
      verifier,
    })
  }

  const authErr = statusToError(resp.status, verifier)
  if (authErr) {
    logVerifyResult(cfg, verifier, endpoint, resp.status, bodyText)
    throw authErr
  }

  if (bodyText === '') {
    return {}
  }
  try {
    return JSON.parse(bodyText)
  } catch (err) {
    throw new OctoAuthError('infra-failure', 'decode verify response', {
      cause: err,
      verifier,
    })
  }
}

/**
 * statusToError converts an HTTP status code to a typed OctoAuthError or
 * undefined for 2xx. Factored out so tests can table-drive the mapping
 * without spinning up a mock server.
 */
export function statusToError(
  status: number,
  verifier: PrincipalKind,
): OctoAuthError | undefined {
  if (status >= 200 && status < 300) return undefined
  if (status === 401) {
    return new OctoAuthError('invalid-credential', 'server rejected credential', {
      verifier,
    })
  }
  if (status === 403) {
    return new OctoAuthError('disabled', 'credential disabled', { verifier })
  }
  return new OctoAuthError('infra-failure', `unexpected status ${status}`, {
    verifier,
  })
}

function logVerifyResult(
  cfg: ResolvedConfig,
  verifier: PrincipalKind,
  endpoint: string,
  status: number,
  body: string,
): void {
  const snippet = body.length > MAX_LOGGED_BODY_BYTES
    ? body.slice(0, MAX_LOGGED_BODY_BYTES)
    : body
  cfg.logger.debug('octoauth: verify response', {
    verifier,
    endpoint,
    status,
    body_snippet: snippet,
  })
}

/**
 * VerifyContext bundles the moving parts a verifier needs on every verify
 * call: cache keys, elapsed timer, and the shared config.
 */
export class VerifyContext {
  readonly cfg: ResolvedConfig
  readonly verifier: PrincipalKind
  readonly posKey: string
  readonly negKey: string
  readonly ttlMs: number
  private readonly startMs: number

  constructor(
    cfg: ResolvedConfig,
    verifier: PrincipalKind,
    keyPrefix: 's:' | 'b:' | 'k:',
    credential: string,
    ttlMs: number,
  ) {
    this.cfg = cfg
    this.verifier = verifier
    const base = cfg.hashCacheKey ? hashCacheKey(credential) : credential
    this.posKey = keyPrefix + base
    this.negKey = this.posKey + ':neg'
    this.ttlMs = ttlMs
    this.startMs = Date.now()
  }

  /**
   * lookupCache returns { principal, error, hit }. A hit is either a positive
   * (principal set, error undefined) or negative (principal undefined, error
   * set). On miss, both are undefined and hit=false.
   */
  async lookupCache(): Promise<{
    principal?: Principal
    error?: OctoAuthError
    hit: boolean
  }> {
    const pos = await this.cfg.cache.get(this.posKey)
    if (pos.found && isPrincipal(pos.value)) {
      return { principal: pos.value, hit: true }
    }
    const neg = await this.cfg.cache.get(this.negKey)
    if (neg.found && neg.value instanceof OctoAuthError) {
      return { error: neg.value, hit: true }
    }
    return { hit: false }
  }

  /**
   * finalize records metrics and caches the outcome. Positive results are
   * stored under posKey with ttl; invalid-credential / disabled are stored
   * under negKey with negativeTtlMs. Infra failures are NOT cached (so a
   * recovering upstream is not blocked behind a stale reject).
   */
  async finalizeSuccess(p: Principal): Promise<Principal> {
    const elapsed = Date.now() - this.startMs
    await this.cfg.cache.set(this.posKey, p, this.ttlMs)
    this.cfg.metrics.observeVerifyDuration(
      this.verifier,
      VERIFY_RESULT_MISS_OK,
      elapsed,
    )
    return clonePrincipal(p)
  }

  async finalizeError(err: unknown): Promise<never> {
    const elapsed = Date.now() - this.startMs
    if (err instanceof OctoAuthError) {
      this.cfg.metrics.incErrorByKind(this.verifier, err.kind)
      if (err.kind === 'invalid-credential' || err.kind === 'disabled') {
        await this.cfg.cache.set(this.negKey, err, this.cfg.negativeTtlMs)
        this.cfg.metrics.observeVerifyDuration(
          this.verifier,
          VERIFY_RESULT_AUTH_ERR,
          elapsed,
        )
        throw err
      }
      this.cfg.metrics.observeVerifyDuration(
        this.verifier,
        VERIFY_RESULT_INFRA,
        elapsed,
      )
      throw err
    }
    this.cfg.metrics.observeVerifyDuration(
      this.verifier,
      VERIFY_RESULT_INFRA,
      elapsed,
    )
    throw err
  }

  /**
   * recordCacheHit stamps metrics for a cache hit and returns a defensive
   * clone of the cached Principal, or throws the cached error.
   */
  recordCacheHit(p?: Principal, err?: OctoAuthError): Principal {
    const elapsed = Date.now() - this.startMs
    this.cfg.metrics.incCacheHit(this.verifier, true)
    this.cfg.metrics.observeVerifyDuration(
      this.verifier,
      VERIFY_RESULT_HIT,
      elapsed,
    )
    if (err) throw err
    if (!p) {
      // Defensive: neither positive nor negative — treat as miss.
      throw new OctoAuthError('infra-failure', 'cache hit with no value', {
        verifier: this.verifier,
      })
    }
    return clonePrincipal(p)
  }

  recordCacheMiss(): void {
    this.cfg.metrics.incCacheHit(this.verifier, false)
  }
}

function isPrincipal(v: unknown): v is Principal {
  if (typeof v !== 'object' || v === null) return false
  const p = v as Principal
  if (typeof p.kind !== 'string') return false
  if (typeof p.uid !== 'string') return false
  if (typeof p.context !== 'object' || p.context === null) return false
  if (typeof p.context.kind !== 'string') return false
  return true
}
