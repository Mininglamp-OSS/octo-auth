package internalhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNotifyServer records incoming notify requests and can be configured
// to reply with any status/body.
type mockNotifyServer struct {
	mu       sync.Mutex
	requests []recordedNotify
	status   int
	body     string
	srv      *httptest.Server
}

type recordedNotify struct {
	method string
	path   string
	header http.Header
	body   []byte
}

func newMockNotifyServer(t *testing.T) *mockNotifyServer {
	t.Helper()
	m := &mockNotifyServer{status: http.StatusOK, body: `{"ok":true}`}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 128)
		buf := make([]byte, 256)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				body = append(body, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		m.mu.Lock()
		m.requests = append(m.requests, recordedNotify{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   body,
		})
		status := m.status
		body2 := m.body
		m.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body2))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockNotifyServer) setReply(status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = status
	m.body = body
}

func (m *mockNotifyServer) all() []recordedNotify {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]recordedNotify, len(m.requests))
	copy(out, m.requests)
	return out
}

func TestNewNotifyClientMissingBaseURL(t *testing.T) {
	t.Setenv("TEST_TOK", "abc")
	_, err := NewNotifyClient(NotifyConfig{TokenEnvVar: "TEST_TOK"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BaseURL")
}

func TestNewNotifyClientMissingTokenEnvVar(t *testing.T) {
	_, err := NewNotifyClient(NotifyConfig{BaseURL: "http://example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TokenEnvVar")
}

func TestNewNotifyClientEnvNotSet(t *testing.T) {
	// Explicitly unset to prevent leakage from surrounding shell.
	t.Setenv("SUMMARY_NOTIFY_TOKEN_MISSING_XYZ", "")
	_, err := NewNotifyClient(NotifyConfig{
		BaseURL:     "http://example.com",
		TokenEnvVar: "SUMMARY_NOTIFY_TOKEN_MISSING_XYZ",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fail-closed")
}

func TestNewNotifyClientHappyPath(t *testing.T) {
	t.Setenv("TEST_TOK", "secret-abc-123456789012345678")
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     "http://example.com",
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)
	require.NotNil(t, c)
	assert.Equal(t, "http://example.com", c.baseURL)
	assert.Equal(t, defaultNotifyPath, c.path)
	assert.Equal(t, "secret-abc-123456789012345678", c.token)
	assert.Equal(t, DefaultNotifyTimeout, c.client.Timeout)
}

func TestNewNotifyClientCustomTimeoutAndPath(t *testing.T) {
	t.Setenv("TEST_TOK", "secret-abc-123456789012345678")
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     "http://example.com",
		TokenEnvVar: "TEST_TOK",
		Timeout:     3 * time.Second,
		NotifyPath:  "/v2/internal/notify",
	})
	require.NoError(t, err)
	assert.Equal(t, 3*time.Second, c.client.Timeout)
	assert.Equal(t, "/v2/internal/notify", c.path)
}

func TestNotifyClientSendSuccess(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	ms := newMockNotifyServer(t)
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     ms.srv.URL,
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)

	err = c.Send(context.Background(), NotifyRequest{
		ChannelID: "chan-1",
		Message:   "hello",
	})
	require.NoError(t, err)

	reqs := ms.all()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].method)
	assert.Equal(t, defaultNotifyPath, reqs[0].path)
	assert.Equal(t, "shhhh-do-not-log-this-verbatim", reqs[0].header.Get("X-Internal-Token"))
	assert.Equal(t, "application/json", reqs[0].header.Get("Content-Type"))
	assert.JSONEq(t, `{"channel_id":"chan-1","message":"hello"}`, string(reqs[0].body))
}

func TestNotifyClientSendRawBodyOverride(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	ms := newMockNotifyServer(t)
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     ms.srv.URL,
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)

	raw := json.RawMessage(`{"custom_key":"custom_value","nested":{"a":1}}`)
	err = c.Send(context.Background(), NotifyRequest{
		ChannelID: "ignored",
		Message:   "also-ignored",
		RawBody:   raw,
	})
	require.NoError(t, err)

	reqs := ms.all()
	require.Len(t, reqs, 1)
	assert.JSONEq(t, string(raw), string(reqs[0].body))
}

func TestNotifyClientSendNon2xxReturnsError(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	ms := newMockNotifyServer(t)
	ms.setReply(http.StatusInternalServerError, `{"server-error-detail":"leaky"}`)
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     ms.srv.URL,
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)

	err = c.Send(context.Background(), NotifyRequest{Message: "hi"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
	// Anti-enumeration: server body must not appear in the returned error.
	assert.NotContains(t, err.Error(), "server-error-detail")
	assert.NotContains(t, err.Error(), "leaky")
}

func TestNotifyClientSendNetworkError(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	ms := newMockNotifyServer(t)
	url := ms.srv.URL
	ms.srv.Close()
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     url,
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)

	err = c.Send(context.Background(), NotifyRequest{Message: "hi"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "notify request failed")
}

func TestNotifyClientSendContextCanceled(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	ms := newMockNotifyServer(t)
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     ms.srv.URL,
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = c.Send(ctx, NotifyRequest{Message: "hi"})
	require.Error(t, err)
}

// TestNotifyClientNoTokenLeakInLog runs a full happy-path Send with a
// captured slog output and asserts the raw token never appears in the log
// stream. Only the masked prefix ("shhhh-do...") is allowed.
func TestNotifyClientNoTokenLeakInLog(t *testing.T) {
	rawToken := "shhhh-do-not-log-this-verbatim-secret"
	t.Setenv("TEST_TOK", rawToken)
	ms := newMockNotifyServer(t)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     ms.srv.URL,
		TokenEnvVar: "TEST_TOK",
		Logger:      logger,
	})
	require.NoError(t, err)

	err = c.Send(context.Background(), NotifyRequest{Message: "hi"})
	require.NoError(t, err)

	logs := buf.String()
	assert.NotContains(t, logs, rawToken, "raw token MUST NOT appear in logs")
	// Sanity: the masked prefix should be there so we know the log actually fired.
	assert.Contains(t, logs, maskToken(rawToken))
}

func TestMaskTokenShortInputs(t *testing.T) {
	// Empty stays empty (nothing to fingerprint).
	assert.Equal(t, "", maskToken(""))
	// Non-empty inputs → sha256:<6 hex chars> (24-bit fingerprint).
	assert.Regexp(t, `^sha256:[0-9a-f]{6}$`, maskToken("short"))
	assert.Regexp(t, `^sha256:[0-9a-f]{6}$`, maskToken("12345678"))
	// Same input → same fingerprint (correlation-friendly).
	assert.Equal(t, maskToken("abc"), maskToken("abc"))
	// Different inputs → different fingerprints (with overwhelming probability).
	assert.NotEqual(t, maskToken("abc"), maskToken("abd"))
	// Fingerprint MUST NOT contain the raw secret or a meaningful prefix.
	raw := "XYZ-live-Kj8mNqPwRt7VaBcDeF"
	masked := maskToken(raw)
	assert.NotContains(t, masked, raw)
	assert.NotContains(t, masked, raw[:8])
	assert.NotContains(t, masked, raw[:4])
}

// TestNotifyClientAcceptsWideStatusRange verifies 2xx statuses other than
// 200 are also treated as success.
func TestNotifyClientAcceptsWideStatusRange(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	for _, status := range []int{200, 201, 202, 204, 299} {
		ms := newMockNotifyServer(t)
		ms.setReply(status, "")
		c, err := NewNotifyClient(NotifyConfig{
			BaseURL:     ms.srv.URL,
			TokenEnvVar: "TEST_TOK",
		})
		require.NoError(t, err)
		assert.NoError(t, c.Send(context.Background(), NotifyRequest{Message: "x"}),
			"status %d should be success", status)
	}
}

// TestNotifyClientRawBodyRoundtrip verifies that a caller-provided raw
// JSON body is not mangled by the marshaller and reaches the server byte-
// exactly.
func TestNotifyClientRawBodyRoundtrip(t *testing.T) {
	t.Setenv("TEST_TOK", "shhhh-do-not-log-this-verbatim")
	ms := newMockNotifyServer(t)
	c, err := NewNotifyClient(NotifyConfig{
		BaseURL:     ms.srv.URL,
		TokenEnvVar: "TEST_TOK",
	})
	require.NoError(t, err)

	raw := json.RawMessage(`{"a":[1,2,3],"b":"unicode-测试"}`)
	require.NoError(t, c.Send(context.Background(), NotifyRequest{RawBody: raw}))

	reqs := ms.all()
	require.Len(t, reqs, 1)
	assert.Equal(t, string(raw), strings.TrimSpace(string(reqs[0].body)))
}
