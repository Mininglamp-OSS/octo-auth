package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// promCollector is the Prometheus-backed Collector. Registers seven
// metrics on the supplied Registerer at construction time; subsequent
// reports are direct counter/histogram updates.
//
// Label cardinality invariants (enforced by TestPrometheusLabelCardinality):
//   - `kind`   is bounded to {user, bot, apikey}
//   - `result` is bounded to {ok, invalid, upstream_error, cache_hit}
//   - `reason` is bounded to {ttl, capacity, manual}
//   - `status_bucket` is bounded to {4xx_client, 5xx_server, timeout}
//   - never ever add a label that contains token / uid / space_id /
//     anything user-supplied — that would explode the timeseries.
type promCollector struct {
	verifyTotal       *prometheus.CounterVec
	verifyDuration    *prometheus.HistogramVec
	cacheHitsTotal    *prometheus.CounterVec
	cacheSize         prometheus.Gauge
	cacheEvictsTotal  *prometheus.CounterVec
	upstreamErrors    *prometheus.CounterVec
	spaceUnverifiedTL prometheus.Counter
}

// NewPrometheusCollector constructs a Collector backed by the supplied
// Registerer. Pass `prometheus.DefaultRegisterer` for the global registry,
// or a `prometheus.NewRegistry()` for an isolated one (tests use the
// latter so the global registry doesn't accumulate stale collectors
// across runs).
//
// Construction is one-shot: re-using the same Registerer for two
// NewPrometheusCollector calls panics on duplicate registration (the
// standard prometheus convention — fail loud rather than silently
// double-count).
func NewPrometheusCollector(reg prometheus.Registerer) Collector {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	factory := promauto.With(reg)
	return &promCollector{
		verifyTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "octoauth_verify_total",
			Help: "Verification calls by token kind and result.",
		}, []string{"kind", "result"}),
		verifyDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "octoauth_verify_duration_seconds",
			Help:    "Verification call latency in seconds.",
			Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		}, []string{"kind"}),
		cacheHitsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "octoauth_cache_hits_total",
			Help: "Verify-cache hits by token kind.",
		}, []string{"kind"}),
		cacheSize: factory.NewGauge(prometheus.GaugeOpts{
			Name: "octoauth_cache_size",
			Help: "Current number of entries in the verify cache.",
		}),
		cacheEvictsTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "octoauth_cache_evicts_total",
			Help: "Cache evictions by reason (ttl / capacity / manual).",
		}, []string{"reason"}),
		upstreamErrors: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "octoauth_upstream_errors_total",
			Help: "Non-2xx responses from octo-server, bucketed by status (4xx_client / 5xx_server / timeout).",
		}, []string{"kind", "status_bucket"}),
		spaceUnverifiedTL: factory.NewCounter(prometheus.CounterOpts{
			Name: "octoauth_space_unverified_total",
			Help: "X-Space-Id accepted without context_included=true (compatibility window with pre-v1 octo-server).",
		}),
	}
}

func (p *promCollector) ObserveVerify(kind, result string, dur float64) {
	p.verifyTotal.WithLabelValues(kind, result).Inc()
	p.verifyDuration.WithLabelValues(kind).Observe(dur)
}
func (p *promCollector) ObserveCacheHit(kind string)        { p.cacheHitsTotal.WithLabelValues(kind).Inc() }
func (p *promCollector) ObserveCacheEvict(reason string)    { p.cacheEvictsTotal.WithLabelValues(reason).Inc() }
func (p *promCollector) ObserveSpaceUnverified()            { p.spaceUnverifiedTL.Inc() }
func (p *promCollector) ObserveUpstreamError(k, b string)   { p.upstreamErrors.WithLabelValues(k, b).Inc() }

// SetCacheSize is an SDK-internal hook (not part of Collector) for the
// cache layer to keep the gauge in sync. Defined on the concrete type
// so callers must type-assert if they want it.
func (p *promCollector) SetCacheSize(n int) {
	p.cacheSize.Set(float64(n))
}
