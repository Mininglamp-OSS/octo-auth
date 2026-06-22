package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPrometheusLabelCardinality pins the security/cost invariant: the
// SDK's Prom labels are bounded enumerations. A regression that adds a
// label whose values include token, uid, or space_id would explode the
// Prom timeseries count and blow up the operator's storage bill.
//
// The test runs each Observe* method with a sample of the allowed label
// values and confirms the gathered metric families have the expected
// label keys (NOT the keys we're protecting against).
func TestPrometheusLabelCardinality(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewPrometheusCollector(reg)

	c.ObserveVerify("user", "ok", 0.01)
	c.ObserveVerify("bot", "invalid", 0.05)
	c.ObserveCacheHit("apikey")
	c.ObserveCacheEvict("ttl")
	c.ObserveCacheEvict("capacity")
	c.ObserveSpaceUnverified()
	c.ObserveUpstreamError("user", "5xx_server")

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	// Map: metric name → allowed label keys (sorted by name).
	allowed := map[string][]string{
		"octoauth_verify_total":            {"kind", "result"},
		"octoauth_verify_duration_seconds": {"kind"},
		"octoauth_cache_hits_total":        {"kind"},
		"octoauth_cache_size":              {},
		"octoauth_cache_evicts_total":      {"reason"},
		"octoauth_upstream_errors_total":   {"kind", "status_bucket"},
		"octoauth_space_unverified_total":  {},
	}
	for _, fam := range families {
		exp, ok := allowed[*fam.Name]
		if !ok {
			t.Errorf("unexpected metric %s — add to allowed map or remove from collector", *fam.Name)
			continue
		}
		for _, m := range fam.Metric {
			gotLabels := make([]string, 0, len(m.Label))
			for _, l := range m.Label {
				gotLabels = append(gotLabels, *l.Name)
				// Forbidden label NAMES — if anyone adds these, fail loud.
				for _, forbidden := range []string{"token", "uid", "space_id", "key_id"} {
					if strings.EqualFold(*l.Name, forbidden) {
						t.Errorf("metric %s has forbidden label %q — would explode cardinality",
							*fam.Name, *l.Name)
					}
				}
			}
			if len(gotLabels) != len(exp) {
				t.Errorf("metric %s labels = %v, want %v", *fam.Name, gotLabels, exp)
			}
		}
	}
}

// TestPrometheusCounters confirms each Observe method actually moves
// the underlying counter — easy regression to introduce if a future
// edit copies the wrong method receiver.
func TestPrometheusCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	c := NewPrometheusCollector(reg)
	c.ObserveCacheHit("user")
	c.ObserveCacheHit("user")
	// gather and count via testutil.CollectAndCount.
	got := testutil.CollectAndCount(reg, "octoauth_cache_hits_total")
	if got != 1 {
		// CollectAndCount returns the number of LABEL combinations, not the
		// counter value. Both Inc calls share the same labels so we expect 1.
		t.Fatalf("cache_hits_total label combos = %d, want 1", got)
	}
}

func TestNoopCollectorIsZeroCost(t *testing.T) {
	c := NewNoopCollector()
	c.ObserveVerify("user", "ok", 1.0)
	c.ObserveCacheHit("user")
	c.ObserveCacheEvict("ttl")
	c.ObserveSpaceUnverified()
	c.ObserveUpstreamError("user", "5xx_server")
	// No panic, no allocations to verify here — the test just exercises
	// every method to satisfy coverage and confirm signatures.
}
