/**
 * Metrics collector interface + no-op default.
 *
 * See design doc §11 and Go SDK's metrics.go. Implementations must be safe
 * for concurrent use and return quickly — verifiers call these on the request
 * hot path.
 */

import type { PrincipalKind, Verifier as _Verifier } from './verifier.js'
import type { ErrorKind } from './errors.js'

/** VerifyResult tags used for the ObserveVerifyDuration `result` argument. */
export type VerifyResult = 'hit' | 'miss-ok' | 'miss-err' | 'error'

/**
 * MetricsCollector receives internal SDK telemetry. Users typically plug their
 * own Prometheus / OTLP-backed implementation.
 */
export interface MetricsCollector {
  observeVerifyDuration(
    verifier: PrincipalKind,
    result: VerifyResult | string,
    ms: number,
  ): void
  incCacheHit(verifier: PrincipalKind, hit: boolean): void
  incErrorByKind(verifier: PrincipalKind, kind: ErrorKind): void
}

/** noopMetrics discards every observation. Default when Config.metrics is unset. */
export const noopMetrics: MetricsCollector = {
  observeVerifyDuration(_v, _r, _ms) {},
  incCacheHit(_v, _h) {},
  incErrorByKind(_v, _k) {},
}
