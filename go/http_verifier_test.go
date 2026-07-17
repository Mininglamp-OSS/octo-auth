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
