package octoauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNoopMetricsDoesNotPanic(t *testing.T) {
	var m MetricsCollector = NoopMetrics{}
	assert.NotPanics(t, func() {
		m.ObserveVerifyDuration(KindSession, "hit", 42*time.Millisecond)
		m.ObserveVerifyDuration(KindBot, "miss-ok", 100*time.Millisecond)
		m.IncCacheHit(KindAPIKey, true)
		m.IncCacheHit(KindSession, false)
		m.IncErrorByKind(KindBot, ErrKindInvalidCredential)
		m.IncErrorByKind(KindSession, ErrKindInfraFailure)
	})
}
