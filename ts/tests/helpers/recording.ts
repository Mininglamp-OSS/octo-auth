/**
 * Small in-mem test double for MetricsCollector so tests can assert
 * observation counts without needing a real Prometheus/OTLP client.
 */

import type { MetricsCollector, VerifyResult } from '../../src/index.js'
import type { ErrorKind, PrincipalKind } from '../../src/index.js'

export interface RecordedMetrics {
  durations: Array<{ verifier: PrincipalKind; result: string; ms: number }>
  cacheHits: Array<{ verifier: PrincipalKind; hit: boolean }>
  errors: Array<{ verifier: PrincipalKind; kind: ErrorKind }>
}

export function newRecordingMetrics(): MetricsCollector & {
  recorded: RecordedMetrics
} {
  const recorded: RecordedMetrics = {
    durations: [],
    cacheHits: [],
    errors: [],
  }
  return {
    recorded,
    observeVerifyDuration(verifier, result, ms) {
      recorded.durations.push({ verifier, result: result as VerifyResult, ms })
    },
    incCacheHit(verifier, hit) {
      recorded.cacheHits.push({ verifier, hit })
    },
    incErrorByKind(verifier, kind) {
      recorded.errors.push({ verifier, kind })
    },
  }
}

/** In-mem logger double that records every debug call. */
export interface RecordedLog {
  messages: Array<{ level: string; message: string; meta?: Record<string, unknown> }>
}

export function newRecordingLogger(): {
  logger: {
    debug: (m: string, meta?: Record<string, unknown>) => void
    info: (m: string, meta?: Record<string, unknown>) => void
    warn: (m: string, meta?: Record<string, unknown>) => void
    error: (m: string, meta?: Record<string, unknown>) => void
  }
  recorded: RecordedLog
} {
  const recorded: RecordedLog = { messages: [] }
  const mk =
    (level: string) => (message: string, meta?: Record<string, unknown>) => {
      recorded.messages.push(
        meta === undefined ? { level, message } : { level, message, meta },
      )
    }
  return {
    logger: {
      debug: mk('debug'),
      info: mk('info'),
      warn: mk('warn'),
      error: mk('error'),
    },
    recorded,
  }
}
