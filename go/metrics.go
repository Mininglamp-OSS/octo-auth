package octoauth

import "time"

// MetricsCollector receives internal SDK telemetry. Implementations MUST be
// safe for concurrent use and MUST return quickly; verifiers call these
// methods on the request hot path.
//
// See design doc §11 for the built-in call sites:
//   - ObserveVerifyDuration is called on every Verify with the observed
//     latency and a `result` tag (one of "hit", "miss-ok", "miss-err",
//     "error").
//   - IncCacheHit is called on every cache lookup with hit=true|false.
//   - IncErrorByKind is called whenever a Verify returns a non-nil error.
type MetricsCollector interface {
	ObserveVerifyDuration(verifier PrincipalKind, result string, duration time.Duration)
	IncCacheHit(verifier PrincipalKind, hit bool)
	IncErrorByKind(verifier PrincipalKind, kind ErrorKind)
}

// NoopMetrics is a [MetricsCollector] that discards every observation. It is
// the default when [Config.Metrics] is nil; users plug their own Prometheus
// or OTLP-backed implementation to opt in.
type NoopMetrics struct{}

// ObserveVerifyDuration implements [MetricsCollector].
func (NoopMetrics) ObserveVerifyDuration(_ PrincipalKind, _ string, _ time.Duration) {}

// IncCacheHit implements [MetricsCollector].
func (NoopMetrics) IncCacheHit(_ PrincipalKind, _ bool) {}

// IncErrorByKind implements [MetricsCollector].
func (NoopMetrics) IncErrorByKind(_ PrincipalKind, _ ErrorKind) {}
