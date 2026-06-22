package metrics

// noopCollector is a zero-cost Collector. Used by tests and by services
// that don't run Prometheus.
type noopCollector struct{}

// NewNoopCollector returns a Collector that does nothing. Safe to share
// across goroutines (no state).
func NewNoopCollector() Collector { return noopCollector{} }

func (noopCollector) ObserveVerify(string, string, float64) {}
func (noopCollector) ObserveCacheHit(string)                {}
func (noopCollector) ObserveCacheEvict(string)              {}
func (noopCollector) ObserveSpaceUnverified()               {}
func (noopCollector) ObserveUpstreamError(string, string)   {}
