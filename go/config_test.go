package octoauth

import (
	"errors"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyDefaultsFillsZeroValues(t *testing.T) {
	cfg := &Config{BaseURL: "http://example.com"}
	applyDefaults(cfg)

	require.NotNil(t, cfg.HTTPClient)
	assert.Equal(t, DefaultHTTPTimeout, cfg.HTTPClient.Timeout)
	require.NotNil(t, cfg.Cache)
	require.NotNil(t, cfg.Metrics)
	_, ok := cfg.Metrics.(NoopMetrics)
	assert.True(t, ok, "default metrics must be NoopMetrics")
	require.NotNil(t, cfg.Logger)
	require.NotNil(t, cfg.ErrorMapper)
	assert.Equal(t, DefaultSessionTTL, cfg.SessionTTL)
	assert.Equal(t, DefaultBotTTL, cfg.BotTTL)
	assert.Equal(t, DefaultAPIKeyTTL, cfg.APIKeyTTL)
	assert.Equal(t, DefaultNegativeTTL, cfg.NegativeTTL)
	require.NotNil(t, cfg.RequestIncludeContext)
	assert.True(t, *cfg.RequestIncludeContext, "RequestIncludeContext defaults to true")
	require.NotNil(t, cfg.HashCacheKey)
	assert.True(t, *cfg.HashCacheKey, "HashCacheKey defaults to true")
}

func TestApplyDefaultsPreservesExplicitValues(t *testing.T) {
	custom := &http.Client{Timeout: 42 * time.Second}
	customCache := NewLRUCache(64)
	customLogger := slog.Default()
	cfg := &Config{
		BaseURL:     "http://example.com",
		HTTPClient:  custom,
		Cache:       customCache,
		Logger:      customLogger,
		SessionTTL:  99 * time.Second,
		BotTTL:      88 * time.Second,
		APIKeyTTL:   77 * time.Second,
		NegativeTTL: 3 * time.Second,
	}
	applyDefaults(cfg)

	assert.Same(t, custom, cfg.HTTPClient)
	assert.Same(t, customLogger, cfg.Logger)
	assert.Equal(t, 99*time.Second, cfg.SessionTTL)
	assert.Equal(t, 88*time.Second, cfg.BotTTL)
	assert.Equal(t, 77*time.Second, cfg.APIKeyTTL)
	assert.Equal(t, 3*time.Second, cfg.NegativeTTL)
}

func TestApplyDefaultsRespectsExplicitFalse(t *testing.T) {
	cfg := &Config{
		BaseURL:               "http://example.com",
		RequestIncludeContext: Ptr(false),
		HashCacheKey:          Ptr(false),
	}
	applyDefaults(cfg)

	require.NotNil(t, cfg.RequestIncludeContext)
	assert.False(t, *cfg.RequestIncludeContext, "explicit Ptr(false) for RequestIncludeContext must survive applyDefaults")
	require.NotNil(t, cfg.HashCacheKey)
	assert.False(t, *cfg.HashCacheKey, "explicit Ptr(false) for HashCacheKey must survive applyDefaults")
}

func TestApplyDefaultsRespectsExplicitTrue(t *testing.T) {
	cfg := &Config{
		BaseURL:               "http://example.com",
		RequestIncludeContext: Ptr(true),
		HashCacheKey:          Ptr(true),
	}
	applyDefaults(cfg)

	require.NotNil(t, cfg.RequestIncludeContext)
	assert.True(t, *cfg.RequestIncludeContext)
	require.NotNil(t, cfg.HashCacheKey)
	assert.True(t, *cfg.HashCacheKey)
}

func TestPtrHelper(t *testing.T) {
	b := Ptr(false)
	require.NotNil(t, b)
	assert.False(t, *b)

	s := Ptr("hello")
	require.NotNil(t, s)
	assert.Equal(t, "hello", *s)
}

func TestApplyDefaultsPanicsOnNil(t *testing.T) {
	assert.Panics(t, func() { applyDefaults(nil) })
}

func TestDefaultErrorMapper(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "invalid_credential",
			err:        &Error{Kind: ErrKindInvalidCredential, Message: "expired"},
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"unauthorized"}`,
		},
		{
			name:       "disabled",
			err:        &Error{Kind: ErrKindDisabled},
			wantStatus: http.StatusForbidden,
			wantBody:   `{"error":"disabled"}`,
		},
		{
			name:       "infra_failure",
			err:        &Error{Kind: ErrKindInfraFailure, Cause: errors.New("dial fail")},
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `{"error":"upstream_unavailable"}`,
		},
		{
			name:       "forbidden",
			err:        &Error{Kind: ErrKindForbidden},
			wantStatus: http.StatusForbidden,
			wantBody:   `{"error":"forbidden"}`,
		},
		{
			name:       "prev2_falls_through_to_internal",
			err:        &Error{Kind: ErrKindPreV2Server},
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal"}`,
		},
		{
			name:       "non_sdk_error_is_internal",
			err:        errors.New("random"),
			wantStatus: http.StatusInternalServerError,
			wantBody:   `{"error":"internal"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, body := DefaultErrorMapper(tc.err)
			assert.Equal(t, tc.wantStatus, status)
			assert.Equal(t, tc.wantBody, string(body))
		})
	}
}

func TestDefaultErrorMapperNoEnumerationLeak(t *testing.T) {
	// Two distinct invalid-credential errors with different messages must
	// produce byte-identical responses so the mapper cannot be probed to
	// distinguish expired from unknown from malformed tokens.
	a := &Error{Kind: ErrKindInvalidCredential, Message: "expired"}
	b := &Error{Kind: ErrKindInvalidCredential, Message: "unknown", Verifier: KindSession}
	statusA, bodyA := DefaultErrorMapper(a)
	statusB, bodyB := DefaultErrorMapper(b)
	assert.Equal(t, statusA, statusB)
	assert.Equal(t, bodyA, bodyB)
}
