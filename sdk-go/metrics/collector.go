// Package metrics defines the Collector interface that octo-auth's SDK
// uses to report verification metrics. Two implementations ship: a
// prometheus.Registerer-backed Collector for services running Prom (the
// default), and a noop Collector for tests and services that don't run
// Prom.
//
// Label cardinality is bounded by design — see prometheus.go for the
// invariants and the TestPrometheusLabelCardinality guard that enforces
// them. Never add a Collector method whose labels include token, uid,
// or space_id — those are unbounded and would explode the Prom
// timeseries cardinality.
package metrics

// Collector is the SDK-internal metrics abstraction. auth.Client and
// auth.Middleware report through this interface; they never import
// prometheus directly. Tests inject a noop or a Prom-backed instance
// with an isolated Registry.
type Collector interface {
	// ObserveVerify records the result of a verify call.
	// kind   ∈ {"user", "bot", "apikey"}
	// result ∈ {"ok", "invalid", "upstream_error", "cache_hit"}
	ObserveVerify(kind string, result string, durationSeconds float64)

	// ObserveCacheHit fires when a verify call short-circuits to a cached
	// identity. Separate from ObserveVerify so dashboards can compute the
	// cache hit rate without subtraction.
	ObserveCacheHit(kind string)

	// ObserveCacheEvict fires on every eviction.
	// reason ∈ {"ttl", "capacity", "manual"}
	ObserveCacheEvict(reason string)

	// ObserveSpaceUnverified increments when the SDK middleware accepts
	// an X-Space-Id without context-included verification. Used to track
	// the fail-closed upgrade window (octo-server modules/auth pre-v1
	// didn't always return spaces[]; the SDK fails open in that case to
	// preserve compatibility).
	ObserveSpaceUnverified()

	// ObserveUpstreamError fires when octo-server returns a non-2xx. The
	// status is bucketed (4xx_client / 5xx_server / timeout) so we don't
	// blow up cardinality with raw HTTP codes.
	ObserveUpstreamError(kind string, statusBucket string)
}
