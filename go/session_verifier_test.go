package octoauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-auth/go/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfig builds a Config wired to a mock server. The negative TTL is
// short so cache-eviction tests do not sleep for the default 5s.
func testConfig(baseURL string) *Config {
	cfg := &Config{
		BaseURL:     baseURL,
		SessionTTL:  time.Minute,
		BotTTL:      time.Minute,
		APIKeyTTL:   time.Minute,
		NegativeTTL: 30 * time.Millisecond,
		Logger:      slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	}
	applyDefaults(cfg)
	return cfg
}

// discardWriter drops slog output so tests don't spam stderr.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// recordingMetrics captures metric calls for assertion.
type recordingMetrics struct {
	durations []struct {
		verifier PrincipalKind
		result   string
	}
	cacheHits map[PrincipalKind]int
	cacheMiss map[PrincipalKind]int
	errKinds  []ErrorKind
}

func newRecordingMetrics() *recordingMetrics {
	return &recordingMetrics{
		cacheHits: make(map[PrincipalKind]int),
		cacheMiss: make(map[PrincipalKind]int),
	}
}

func (r *recordingMetrics) ObserveVerifyDuration(v PrincipalKind, result string, _ time.Duration) {
	r.durations = append(r.durations, struct {
		verifier PrincipalKind
		result   string
	}{v, result})
}
func (r *recordingMetrics) IncCacheHit(v PrincipalKind, hit bool) {
	if hit {
		r.cacheHits[v]++
	} else {
		r.cacheMiss[v]++
	}
}
func (r *recordingMetrics) IncErrorByKind(_ PrincipalKind, k ErrorKind) {
	r.errKinds = append(r.errKinds, k)
}

func TestSessionVerifierHappyPathContextIncluded(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{
		"uid": "u-1",
		"name": "Alice",
		"role": "user",
		"owned_bots": [{"uid":"b-1","name":"Bot 1"},{"uid":"b-2","name":"Bot 2"}],
		"context_included": true,
		"spaces": ["s-1", "s-2"],
		"owned_bots_by_space": {"s-1": ["b-1"], "s-2": ["b-2"]}
	}`)
	cfg := testConfig(ms.URL())
	cfg.Metrics = newRecordingMetrics()
	v := NewSessionVerifier(cfg)

	p, err := v.Verify(context.Background(), "session-token")
	require.NoError(t, err)
	assert.Equal(t, KindSession, p.Kind)
	assert.Equal(t, "u-1", p.UID)
	assert.Equal(t, "Alice", p.Name)
	assert.Equal(t, "user", p.Role)
	assert.Equal(t, []string{"u-1", "b-1", "b-2"}, p.RelatedUIDs)
	assert.Equal(t, ContextIncluded, p.Context.Kind)
	assert.Equal(t, []string{"s-1", "s-2"}, p.Context.Spaces)
	assert.Len(t, p.Context.OwnedBotsBySpace, 2)

	// Verify include=context was on the wire.
	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "include=context", reqs[0].Query)
	assert.Contains(t, string(reqs[0].Body), `"token":"session-token"`)
}

func TestSessionVerifierContextNotIncluded(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK,
		`{"uid":"u-1","context_included":false}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	p, err := v.Verify(context.Background(), "tok")
	require.NoError(t, err)
	assert.Equal(t, ContextNotIncluded, p.Context.Kind)
	assert.Nil(t, p.Context.Spaces)
}

func TestSessionVerifierContextUnknownServer(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	// Missing context_included field entirely — pre-v2 server.
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	p, err := v.Verify(context.Background(), "tok")
	require.NoError(t, err)
	assert.Equal(t, ContextUnknownServer, p.Context.Kind)
}

func TestSessionVerifierIncludeContextDisabled(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	cfg.RequestIncludeContext = Ptr(false)
	v := NewSessionVerifier(cfg)

	p, err := v.Verify(context.Background(), "tok")
	require.NoError(t, err)
	assert.Equal(t, ContextNotRequested, p.Context.Kind)

	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].Query, "include=context must not be sent when disabled")
}

func TestSessionVerifierStatusMapping(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantKind  ErrorKind
		cacheable bool
	}{
		{"401", http.StatusUnauthorized, `{"error":"nope"}`, ErrKindInvalidCredential, true},
		{"403", http.StatusForbidden, `{"error":"disabled"}`, ErrKindDisabled, true},
		{"500", http.StatusInternalServerError, `oops`, ErrKindInfraFailure, false},
		{"502", http.StatusBadGateway, `oops`, ErrKindInfraFailure, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ms := testhelpers.NewMockServer(t)
			ms.SetResponse("/v1/auth/verify", tc.status, tc.body)
			cfg := testConfig(ms.URL())
			v := NewSessionVerifier(cfg)

			_, err := v.Verify(context.Background(), "tok")
			require.Error(t, err)
			var authErr *Error
			require.ErrorAs(t, err, &authErr)
			assert.Equal(t, tc.wantKind, authErr.Kind)
			assert.Equal(t, KindSession, authErr.Verifier)
		})
	}
}

func TestSessionVerifierDecodeError(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `not json`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	_, err := v.Verify(context.Background(), "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestSessionVerifierNetworkFailure(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	url := ms.URL()
	ms.Close() // simulate server down
	cfg := testConfig(url)
	v := NewSessionVerifier(cfg)

	_, err := v.Verify(context.Background(), "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestSessionVerifierEmptyCredentialShortCircuit(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	_, err := v.Verify(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	assert.Empty(t, ms.Requests(), "empty credential must not hit the network")
}

func TestSessionVerifierResponseMissingUID(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"name":"x"}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	_, err := v.Verify(context.Background(), "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestSessionVerifierCachePositive(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1","context_included":true}`)
	cfg := testConfig(ms.URL())
	metrics := newRecordingMetrics()
	cfg.Metrics = metrics
	v := NewSessionVerifier(cfg)

	ctx := context.Background()
	first, err := v.Verify(ctx, "tok")
	require.NoError(t, err)
	second, err := v.Verify(ctx, "tok")
	require.NoError(t, err)

	assert.NotSame(t, first, second, "Verify must return a defensive clone per call")
	assert.Equal(t, first, second, "clones must be value-equal")
	assert.Len(t, ms.Requests(), 1, "second call must hit cache, not network")
	assert.Equal(t, 1, metrics.cacheHits[KindSession])
	assert.Equal(t, 1, metrics.cacheMiss[KindSession])
}

func TestSessionVerifierCallerMutationDoesNotPoisonCache(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK,
		`{"uid":"u-1","name":"orig","role":"member","owned_bots":[{"uid":"b1","name":"Bot 1"}],"context_included":true,"spaces":["s1"]}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	ctx := context.Background()
	first, err := v.Verify(ctx, "tok")
	require.NoError(t, err)

	// Poison every mutable field of the returned Principal — the SDK must
	// still hand back a pristine copy on the next Verify.
	first.UID = "attacker"
	first.Name = "attacker"
	first.Role = "root"
	first.SpaceID = "s-attacker"
	if len(first.RelatedUIDs) > 0 {
		first.RelatedUIDs[0] = "attacker"
	}
	if len(first.Context.Spaces) > 0 {
		first.Context.Spaces[0] = "s-attacker"
	}

	second, err := v.Verify(ctx, "tok")
	require.NoError(t, err)

	assert.Equal(t, "u-1", second.UID)
	assert.Equal(t, "orig", second.Name)
	assert.Equal(t, "member", second.Role)
	assert.Equal(t, "u-1", second.RelatedUIDs[0])
	assert.Equal(t, "s1", second.Context.Spaces[0])
	assert.Len(t, ms.Requests(), 1)
}

func TestSessionVerifierCacheNegative(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusUnauthorized, `{"error":"nope"}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	ctx := context.Background()
	_, err1 := v.Verify(ctx, "tok")
	require.Error(t, err1)
	_, err2 := v.Verify(ctx, "tok")
	require.Error(t, err2)

	assert.ErrorIs(t, err1, ErrInvalidCredential)
	assert.ErrorIs(t, err2, ErrInvalidCredential)
	assert.Len(t, ms.Requests(), 1, "negative result must be cached for NegativeTTL")
}

func TestSessionVerifierCacheNegativeExpiry(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusUnauthorized, `{"error":"nope"}`)
	cfg := testConfig(ms.URL())
	cfg.NegativeTTL = 10 * time.Millisecond
	v := NewSessionVerifier(cfg)

	ctx := context.Background()
	_, _ = v.Verify(ctx, "tok")
	time.Sleep(20 * time.Millisecond)
	_, _ = v.Verify(ctx, "tok")

	assert.Len(t, ms.Requests(), 2, "expired negative entry must refetch")
}

func TestSessionVerifierInfraFailureNotCached(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusInternalServerError, "boom")
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	ctx := context.Background()
	_, err1 := v.Verify(ctx, "tok")
	_, err2 := v.Verify(ctx, "tok")
	require.Error(t, err1)
	require.Error(t, err2)
	assert.Len(t, ms.Requests(), 2, "infra failures MUST NOT be cached")
}

func TestSessionVerifierCacheKeyIsHashed(t *testing.T) {
	// Peek at the raw cache to make sure the raw token never appears in the
	// cache key when HashCacheKey is enabled (the default).
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	_, err := v.Verify(context.Background(), "secret-token")
	require.NoError(t, err)

	expected := "s:c:" + HashCacheKey("secret-token")
	val, ok := cfg.Cache.Get(context.Background(), expected)
	require.True(t, ok, "expected cache key must be hashed")
	require.NotNil(t, val)
}

func TestSessionVerifierContextTimeout(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	_, err := v.Verify(ctx, "tok")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
	assert.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"context error should be reachable via Unwrap")
}

func TestBuildSessionRelatedDeduplicates(t *testing.T) {
	got := buildSessionRelated("u-1", []OwnedBot{
		{UID: "b-1", Name: "Bot 1"},
		{UID: "u-1", Name: "dup self"},
		{UID: "b-1", Name: "dup bot"},
		{UID: "", Name: "empty"},
		{UID: "b-2", Name: "Bot 2"},
	})
	assert.Equal(t, []string{"u-1", "b-1", "b-2"}, got)
}

func TestSessionVerifierURLDoesNotIncludeBearerPrefix(t *testing.T) {
	// Guard against accidental URL smuggling: the URL sent to the mock
	// server must be the base URL + endpoint, nothing else.
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	v := NewSessionVerifier(cfg)

	_, err := v.Verify(context.Background(), "Bearer tok")
	require.NoError(t, err)

	parsed, perr := url.Parse(ms.URL())
	require.NoError(t, perr)
	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.NotContains(t, reqs[0].Path+reqs[0].Query, "Bearer")
	// Sanity: baseURL host was consumed.
	assert.NotEmpty(t, parsed.Host)
}
