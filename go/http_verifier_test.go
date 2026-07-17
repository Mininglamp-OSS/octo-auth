package octoauth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Mininglamp-OSS/octo-auth/go/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusToError(t *testing.T) {
	tests := []struct {
		status   int
		wantNil  bool
		wantKind ErrorKind
	}{
		{200, true, 0},
		{201, true, 0},
		{299, true, 0},
		{400, false, ErrKindInfraFailure},
		{401, false, ErrKindInvalidCredential},
		{403, false, ErrKindDisabled},
		{404, false, ErrKindInfraFailure},
		{500, false, ErrKindInfraFailure},
		{502, false, ErrKindInfraFailure},
		{503, false, ErrKindInfraFailure},
	}
	for _, tc := range tests {
		got := statusToError(tc.status, KindSession)
		if tc.wantNil {
			assert.Nil(t, got, "status %d", tc.status)
			continue
		}
		require.NotNil(t, got, "status %d", tc.status)
		assert.Equal(t, tc.wantKind, got.Kind, "status %d", tc.status)
		assert.Equal(t, KindSession, got.Verifier)
	}
}

func TestDoVerifyRequestSuccess(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/x", http.StatusOK, `{"ok":true}`)
	cfg := testConfig(ms.URL())

	body, err := doVerifyRequest(context.Background(), cfg, "/x", map[string]string{"a": "b"}, KindSession)
	require.NoError(t, err)
	assert.Equal(t, `{"ok":true}`, string(body))

	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, `{"a":"b"}`, string(reqs[0].Body))
	assert.Equal(t, "application/json", reqs[0].Header.Get("Content-Type"))
}

func TestDoVerifyRequestTimeout(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/x", http.StatusOK, `{}`)
	cfg := testConfig(ms.URL())

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err := doVerifyRequest(ctx, cfg, "/x", map[string]string{}, KindSession)
	require.Error(t, err)
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, ErrKindInfraFailure, authErr.Kind)
}

func TestDoVerifyRequestNetworkFailure(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	url := ms.URL()
	ms.Close()
	cfg := testConfig(url)

	_, err := doVerifyRequest(context.Background(), cfg, "/x", map[string]string{}, KindSession)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestDoVerifyRequestBadURL(t *testing.T) {
	cfg := testConfig("http://[::1]:not-a-port")
	_, err := doVerifyRequest(context.Background(), cfg, "/x", map[string]string{}, KindSession)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

// TestDoVerifyRequestRejectsRedirect guards reviewer P1-B: the default
// HTTPClient MUST NOT follow a 307/308, otherwise the POST body — which
// carries the raw credential — would be replayed to the Location target.
// The mock server returns 307 with a Location pointing to an attacker
// endpoint; the SDK should stop at the redirect and surface it as
// InfraFailure (unexpected status), and the attacker endpoint should
// receive zero requests.
func TestDoVerifyRequestRejectsRedirect(t *testing.T) {
	attacker := testhelpers.NewMockServer(t)
	attacker.SetResponse("/steal", http.StatusOK, `{"stolen":true}`)

	victim := testhelpers.NewMockServer(t)
	victim.SetResponseFull("/x", testhelpers.StubResponse{
		Status: http.StatusTemporaryRedirect, // 307
		Body:   "",
		Headers: http.Header{
			"Location": []string{attacker.URL() + "/steal"},
		},
	})
	cfg := testConfig(victim.URL())

	// A "credential-shaped" body — this is what would leak if the client
	// followed the redirect.
	body := map[string]string{"token": "SECRET-CRED-abc123"}
	_, err := doVerifyRequest(context.Background(), cfg, "/x", body, KindSession)
	require.Error(t, err)
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, ErrKindInfraFailure, authErr.Kind, "3xx must map to InfraFailure, not silently follow")

	// Victim server was hit once (the initial POST); attacker server MUST NOT
	// have been contacted.
	assert.Len(t, victim.Requests(), 1, "victim receives the initial POST")
	assert.Empty(t, attacker.Requests(), "attacker MUST NOT receive the redirected body — credential leak blocked")
}

// TestDoVerifyRequestRejectsPermanentRedirect covers the 308 sibling case.
func TestDoVerifyRequestRejectsPermanentRedirect(t *testing.T) {
	attacker := testhelpers.NewMockServer(t)
	attacker.SetResponse("/steal", http.StatusOK, `{}`)

	victim := testhelpers.NewMockServer(t)
	victim.SetResponseFull("/x", testhelpers.StubResponse{
		Status: http.StatusPermanentRedirect, // 308
		Headers: http.Header{
			"Location": []string{attacker.URL() + "/steal"},
		},
	})
	cfg := testConfig(victim.URL())

	_, err := doVerifyRequest(context.Background(), cfg, "/x", map[string]string{"api_key": "uk_secret"}, KindAPIKey)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
	assert.Empty(t, attacker.Requests(), "308 must also be blocked (credential leak)")
}

// TestDoVerifyRequestBoundedBody guards reviewer P1-G: a malicious or
// compromised upstream that streams a response body larger than
// maxVerifyBodyBytes MUST NOT be able to OOM the SDK consumer. The
// oversize is surfaced as InfraFailure rather than absorbed.
func TestDoVerifyRequestBoundedBody(t *testing.T) {
	oversized := strings.Repeat("A", maxVerifyBodyBytes+1024) // just over cap
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/x", http.StatusOK, oversized)
	cfg := testConfig(ms.URL())

	_, err := doVerifyRequest(context.Background(), cfg, "/x", map[string]string{}, KindSession)
	require.Error(t, err)
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, ErrKindInfraFailure, authErr.Kind)
	assert.Contains(t, authErr.Message, "exceeds")
}

// TestDoVerifyRequestBodyAtCapSucceeds proves the LimitReader's off-by-one
// is correct: a body exactly maxVerifyBodyBytes bytes still parses.
func TestDoVerifyRequestBodyAtCapSucceeds(t *testing.T) {
	// Build a JSON body whose length is exactly maxVerifyBodyBytes. Pad the
	// UID string to make up the remaining bytes.
	prefix := `{"uid":"`
	suffix := `"}`
	pad := strings.Repeat("x", maxVerifyBodyBytes-len(prefix)-len(suffix))
	body := prefix + pad + suffix
	require.Len(t, body, maxVerifyBodyBytes)

	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/x", http.StatusOK, body)
	cfg := testConfig(ms.URL())

	got, err := doVerifyRequest(context.Background(), cfg, "/x", map[string]string{}, KindSession)
	require.NoError(t, err, "body of exactly maxVerifyBodyBytes MUST be accepted")
	require.NotNil(t, got)
}

// TestNewVerifyContextCacheKeyEncodesIncludeContext guards reviewer P1-C:
// two verifier instances that share a Cache but disagree on
// RequestIncludeContext MUST produce different cache keys, otherwise a
// no-context Principal (ContextNotRequested → enrich no-op) could be
// served to a caller expecting ContextIncluded and silently skip
// X-Space-Id membership validation.
func TestNewVerifyContextCacheKeyEncodesIncludeContext(t *testing.T) {
	cfgOn := &Config{BaseURL: "http://example.com", RequestIncludeContext: Ptr(true)}
	cfgOff := &Config{BaseURL: "http://example.com", RequestIncludeContext: Ptr(false)}
	applyDefaults(cfgOn)
	applyDefaults(cfgOff)

	vcOn := newVerifyContext(cfgOn, KindSession, "s:", "same-cred", cfgOn.SessionTTL)
	vcOff := newVerifyContext(cfgOff, KindSession, "s:", "same-cred", cfgOff.SessionTTL)

	assert.NotEqual(t, vcOn.posKey, vcOff.posKey, "cache keys MUST differ when RequestIncludeContext differs")
	assert.NotEqual(t, vcOn.negKey, vcOff.negKey, "negative cache keys MUST differ too")
	assert.Contains(t, vcOn.posKey, "s:c:", "include=context path uses 'c:' tag")
	assert.Contains(t, vcOff.posKey, "s:n:", "no-context path uses 'n:' tag")

	// Same flag setting → same key (cache correctness across process life).
	vcOn2 := newVerifyContext(cfgOn, KindSession, "s:", "same-cred", cfgOn.SessionTTL)
	assert.Equal(t, vcOn.posKey, vcOn2.posKey)
}

// TestNewVerifyContextCacheKeyUniformAcrossPrefixes confirms the "c:"/"n:"
// tag is applied to bot and apikey prefixes too, keeping key layout
// uniform even though bot ignores the flag.
func TestNewVerifyContextCacheKeyUniformAcrossPrefixes(t *testing.T) {
	cfg := &Config{BaseURL: "http://example.com"}
	applyDefaults(cfg) // RequestIncludeContext defaults to Ptr(true) → "c:"

	sessionKey := newVerifyContext(cfg, KindSession, "s:", "x", cfg.SessionTTL).posKey
	botKey := newVerifyContext(cfg, KindBot, "b:", "x", cfg.BotTTL).posKey
	apiKey := newVerifyContext(cfg, KindAPIKey, "k:", "x", cfg.APIKeyTTL).posKey

	assert.True(t, strings.HasPrefix(sessionKey, "s:c:"))
	assert.True(t, strings.HasPrefix(botKey, "b:c:"))
	assert.True(t, strings.HasPrefix(apiKey, "k:c:"))
}

func TestDecodeVerifyResponse(t *testing.T) {
	var out struct {
		Foo string `json:"foo"`
	}
	err := decodeVerifyResponse([]byte(`{"foo":"bar"}`), &out, KindSession)
	require.NoError(t, err)
	assert.Equal(t, "bar", out.Foo)

	err = decodeVerifyResponse([]byte(`not json`), &out, KindSession)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestLogVerifyResultTruncatesBody(t *testing.T) {
	// Just make sure the function does not panic on large / small / nil inputs.
	cfg := testConfig("http://example.com")
	longBody := make([]byte, 4096)
	for i := range longBody {
		longBody[i] = 'x'
	}
	assert.NotPanics(t, func() {
		logVerifyResult(cfg, KindSession, "/x", 500, longBody)
		logVerifyResult(cfg, KindSession, "/x", 401, []byte("short"))
		logVerifyResult(cfg, KindSession, "/x", 200, nil)
		logVerifyResult(nil, KindSession, "/x", 200, nil) // nil cfg guard
	})
}

// wrongTypeCache stores whatever the caller wants under a preset key and
// returns it verbatim, letting lookupCache exercise its type-assertion
// fallback path.
type wrongTypeCache struct {
	entries map[string]any
}

func (c *wrongTypeCache) Get(_ context.Context, key string) (any, bool) {
	v, ok := c.entries[key]
	return v, ok
}
func (c *wrongTypeCache) Set(_ context.Context, key string, value any, _ time.Duration) {
	c.entries[key] = value
}
func (c *wrongTypeCache) Delete(_ context.Context, key string) { delete(c.entries, key) }

func TestLookupCacheWarnsOnPositiveWrongType(t *testing.T) {
	buf := &bytes.Buffer{}
	cfg := &Config{
		BaseURL: "http://example.com",
		Cache:   &wrongTypeCache{entries: map[string]any{"s:abc": "not a Principal"}},
		Logger:  slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	applyDefaults(cfg)

	vc := newVerifyContext(cfg, KindSession, "s:", "abc", cfg.SessionTTL)
	// Force the cache-key lookup to hit the pre-seeded key by bypassing hash.
	vc.posKey = "s:abc"
	vc.negKey = "s:abc:neg"

	p, err, hit := vc.lookupCache(context.Background())
	assert.Nil(t, p)
	assert.NoError(t, err)
	assert.False(t, hit, "wrong-type entry must be treated as a miss")

	log := buf.String()
	assert.Contains(t, log, "cache returned wrong type for positive key")
	assert.Contains(t, log, "level=WARN")
}

func TestLookupCacheWarnsOnNegativeWrongType(t *testing.T) {
	buf := &bytes.Buffer{}
	cfg := &Config{
		BaseURL: "http://example.com",
		Cache:   &wrongTypeCache{entries: map[string]any{"s:abc:neg": 42}},
		Logger:  slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	applyDefaults(cfg)

	vc := newVerifyContext(cfg, KindSession, "s:", "abc", cfg.SessionTTL)
	vc.posKey = "s:abc"
	vc.negKey = "s:abc:neg"

	p, err, hit := vc.lookupCache(context.Background())
	assert.Nil(t, p)
	assert.NoError(t, err)
	assert.False(t, hit)

	assert.Contains(t, buf.String(), "cache returned wrong type for negative key")
	assert.True(t, strings.Contains(buf.String(), "level=WARN"))
}
