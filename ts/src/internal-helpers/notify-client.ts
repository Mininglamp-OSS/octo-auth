/**
 * internal-helpers/notify-client — X-Internal-Token producer channel.
 *
 * See design doc §9.1 and Go SDK's internal_helpers/notify_client.go.
 * Constructor reads the token from process.env at build time and throws if
 * empty — a "fail-closed at startup" posture matching Go's NewNotifyClient.
 */

import type { Logger } from '../config.js'
import { consoleLogger } from '../config.js'

/** DefaultNotifyTimeoutMs matches Go's DefaultNotifyTimeout (10s). */
export const DEFAULT_NOTIFY_TIMEOUT_MS = 10_000
const DEFAULT_NOTIFY_PATH = '/v1/internal/notify'

/** NotifyConfig configures a NotifyClient. */
export interface NotifyConfig {
  /** Required. Target service base URL, e.g. https://octo-server:8090. */
  baseUrl: string
  /** Required. Process env var to read the shared secret from. */
  tokenEnvVar: string
  /** Fetch implementation. Defaults to globalThis.fetch. */
  fetch?: typeof globalThis.fetch
  /** Per-request timeout ms. Defaults to 10_000. */
  timeoutMs?: number
  /** Logger. Defaults to consoleLogger. */
  logger?: Logger
  /** Optional path override. Must start with "/" when set. */
  notifyPath?: string
}

/**
 * NotifyRequest is the payload sent to /v1/internal/notify. In v1 the shape
 * is intentionally minimal (channel_id + message); callers whose contract
 * needs a different shape can pass `rawBody` and leave the primary fields
 * empty.
 */
export interface NotifyRequest {
  channelId?: string
  message?: string
  /** When set, this JSON string is sent verbatim; channelId/message ignored. */
  rawBody?: string
}

/**
 * NotifyClient posts service-authenticated notifications via the shared-secret
 * X-Internal-Token producer channel. Instances are safe for concurrent use.
 */
export class NotifyClient {
  private readonly baseUrl: string
  private readonly path: string
  private readonly token: string
  private readonly tokenHint: string
  private readonly fetchImpl: typeof globalThis.fetch
  private readonly timeoutMs: number
  private readonly logger: Logger

  constructor(cfg: NotifyConfig) {
    if (!cfg.baseUrl) {
      throw new Error(
        'octoauth/internal-helpers: NotifyConfig.baseUrl is required',
      )
    }
    if (!cfg.tokenEnvVar) {
      throw new Error(
        'octoauth/internal-helpers: NotifyConfig.tokenEnvVar is required',
      )
    }
    const token = process.env[cfg.tokenEnvVar]
    if (!token) {
      throw new Error(
        `octoauth/internal-helpers: env var "${cfg.tokenEnvVar}" is empty (fail-closed)`,
      )
    }
    this.baseUrl = cfg.baseUrl
    this.path = cfg.notifyPath ?? DEFAULT_NOTIFY_PATH
    this.token = token
    this.tokenHint = maskToken(token)
    if (cfg.fetch !== undefined) {
      this.fetchImpl = cfg.fetch
    } else {
      if (typeof globalThis.fetch !== 'function') {
        throw new Error(
          'octoauth/internal-helpers: globalThis.fetch is not available; pass NotifyConfig.fetch',
        )
      }
      this.fetchImpl = globalThis.fetch.bind(globalThis)
    }
    this.timeoutMs = cfg.timeoutMs ?? DEFAULT_NOTIFY_TIMEOUT_MS
    this.logger = cfg.logger ?? consoleLogger
  }

  /**
   * send posts req to the notify endpoint. Non-2xx status becomes an Error
   * whose message contains ONLY the status code — the response body is NOT
   * included so log scrapers cannot enumerate server-side messages via the
   * caller's error path.
   */
  async send(req: NotifyRequest, signal?: AbortSignal): Promise<void> {
    let body: string
    if (req.rawBody !== undefined && req.rawBody !== '') {
      body = req.rawBody
    } else {
      try {
        body = JSON.stringify({
          channel_id: req.channelId ?? '',
          message: req.message ?? '',
        })
      } catch (err) {
        throw new Error(
          `octoauth/internal-helpers: encode notify request: ${(err as Error).message}`,
        )
      }
    }

    const timeoutCtl = new AbortController()
    const timer = setTimeout(() => timeoutCtl.abort(), this.timeoutMs)
    const composite = signal
      ? AbortSignal.any([signal, timeoutCtl.signal])
      : timeoutCtl.signal
    let resp: Response
    try {
      resp = await this.fetchImpl(this.baseUrl + this.path, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-Internal-Token': this.token,
        },
        body,
        signal: composite,
      })
    } catch (err) {
      this.logger.debug('octoauth/internal-helpers: notify transport error', {
        endpoint: this.path,
        token_hint: this.tokenHint,
      })
      throw new Error(
        `octoauth/internal-helpers: notify request failed: ${(err as Error).message}`,
      )
    } finally {
      clearTimeout(timer)
    }
    // Drain the body so the connection can be reused.
    try {
      await resp.text()
    } catch {
      // Ignore drain errors.
    }
    this.logger.debug('octoauth/internal-helpers: notify sent', {
      endpoint: this.path,
      status: resp.status,
      token_hint: this.tokenHint,
    })
    if (resp.status < 200 || resp.status >= 300) {
      throw new Error(
        `octoauth/internal-helpers: notify failed: status ${resp.status}`,
      )
    }
  }
}

/**
 * newNotifyClient is a convenience factory function equivalent to
 * `new NotifyClient(cfg)`.
 */
export function newNotifyClient(cfg: NotifyConfig): NotifyClient {
  return new NotifyClient(cfg)
}

/**
 * maskToken returns a short prefix + "..." suitable for logs. Even 8
 * characters of an internal shared secret should not appear in application
 * logs verbatim.
 */
export function maskToken(t: string): string {
  if (t.length < 8) return '***'
  return t.slice(0, 8) + '...'
}
