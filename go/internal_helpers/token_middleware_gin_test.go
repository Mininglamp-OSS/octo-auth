package internalhelpers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newGinAdminApp(t *testing.T, envVar, envValue, headerName string) *gin.Engine {
	t.Helper()
	t.Setenv(envVar, envValue)
	engine := gin.New()
	engine.Use(NewInternalTokenGinMiddleware(InternalTokenConfig{
		HeaderName:  headerName,
		TokenEnvVar: envVar,
	}))
	engine.POST("/admin/reload", func(c *gin.Context) {
		c.String(http.StatusOK, "reloaded")
	})
	return engine
}

func doPOST(engine http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/reload", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func TestInternalTokenGinMissingConfigPanics(t *testing.T) {
	assert.Panics(t, func() {
		NewInternalTokenGinMiddleware(InternalTokenConfig{})
	})
	assert.Panics(t, func() {
		NewInternalTokenGinMiddleware(InternalTokenConfig{HeaderName: "X-Foo"})
	})
	assert.Panics(t, func() {
		NewInternalTokenGinMiddleware(InternalTokenConfig{TokenEnvVar: "FOO_TOK"})
	})
}

func TestInternalTokenGinEnvNotSetPanics(t *testing.T) {
	t.Setenv("ADMIN_TOK_XYZ_UNSET", "")
	assert.Panics(t, func() {
		NewInternalTokenGinMiddleware(InternalTokenConfig{
			HeaderName:  "X-Runtime-Admin-Token",
			TokenEnvVar: "ADMIN_TOK_XYZ_UNSET",
		})
	})
}

func TestInternalTokenGinCorrectToken(t *testing.T) {
	engine := newGinAdminApp(t, "ADMIN_TOK", "correct-secret", "X-Runtime-Admin-Token")
	w := doPOST(engine, map[string]string{"X-Runtime-Admin-Token": "correct-secret"})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "reloaded", w.Body.String())
}

func TestInternalTokenGinWrongToken(t *testing.T) {
	engine := newGinAdminApp(t, "ADMIN_TOK", "correct-secret", "X-Runtime-Admin-Token")
	w := doPOST(engine, map[string]string{"X-Runtime-Admin-Token": "wrong-guess"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))
}

func TestInternalTokenGinMissingHeader(t *testing.T) {
	engine := newGinAdminApp(t, "ADMIN_TOK", "correct-secret", "X-Runtime-Admin-Token")
	w := doPOST(engine, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))
}

// TestInternalTokenGinAntiEnumeration proves that "missing header", "empty
// header", "wrong-length token", and "correct-length wrong-value token" all
// produce byte-identical responses so an attacker cannot infer the secret's
// length or existence.
func TestInternalTokenGinAntiEnumeration(t *testing.T) {
	engine := newGinAdminApp(t, "ADMIN_TOK", "correct-secret-12345678", "X-Runtime-Admin-Token")

	responses := map[string]*httptest.ResponseRecorder{
		"missing":        doPOST(engine, nil),
		"empty_value":    doPOST(engine, map[string]string{"X-Runtime-Admin-Token": ""}),
		"short_wrong":    doPOST(engine, map[string]string{"X-Runtime-Admin-Token": "nope"}),
		"same_len_wrong": doPOST(engine, map[string]string{"X-Runtime-Admin-Token": "another-secret-12345678"}),
	}

	// All four should be byte-identical.
	var reference []byte
	for label, r := range responses {
		assert.Equal(t, http.StatusUnauthorized, r.Code, "label=%s", label)
		body := r.Body.Bytes()
		if reference == nil {
			reference = body
			continue
		}
		assert.Equal(t, reference, body, "label=%s response body diverges", label)
	}
}

func TestInternalTokenGinNoTokenLeakInResponseBody(t *testing.T) {
	secret := "very-secret-do-not-leak-12345"
	engine := newGinAdminApp(t, "ADMIN_TOK", secret, "X-Runtime-Admin-Token")
	w := doPOST(engine, map[string]string{"X-Runtime-Admin-Token": "wrong"})
	assert.NotContains(t, w.Body.String(), secret)
}

// TestConstantTimeEqualString covers the exported comparison helper in
// isolation, including the length-mismatch branch that would otherwise
// leak length via early return.
func TestConstantTimeEqualString(t *testing.T) {
	want := []byte("secret-token")

	assert.True(t, constantTimeEqualString("secret-token", want))
	assert.False(t, constantTimeEqualString("secret-token-longer", want))
	assert.False(t, constantTimeEqualString("wrong-token!", want))
	assert.False(t, constantTimeEqualString("", want))
	assert.False(t, constantTimeEqualString("short", want))
}

func TestInternalTokenGinImplementationUsesConstantTimeCompare(t *testing.T) {
	// Sanity: read the source of token_middleware_gin.go and require the
	// crypto/subtle import + ConstantTimeCompare call are present. Guards
	// against a regression that swaps in plain string == comparison.
	//
	// The test lives here rather than as an AST scan to keep the assertion
	// self-contained.
	src, err := readSource("token_middleware_gin.go")
	require.NoError(t, err)
	assert.Contains(t, src, `"crypto/subtle"`)
	assert.Contains(t, src, "ConstantTimeCompare")
}

// --- net/http flavor tests ---

func newNetHTTPAdminHandler(t *testing.T, envVar, envValue, headerName string) http.Handler {
	t.Helper()
	t.Setenv(envVar, envValue)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("reloaded"))
	})
	return WrapInternalTokenNetHTTP(inner, InternalTokenConfig{
		HeaderName:  headerName,
		TokenEnvVar: envVar,
	})
}

func TestInternalTokenNetHTTPCorrectToken(t *testing.T) {
	h := newNetHTTPAdminHandler(t, "ADMIN_TOK_2", "correct-secret", "X-Internal-Token")
	w := doPOST(h, map[string]string{"X-Internal-Token": "correct-secret"})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "reloaded", w.Body.String())
}

func TestInternalTokenNetHTTPWrongToken(t *testing.T) {
	h := newNetHTTPAdminHandler(t, "ADMIN_TOK_2", "correct-secret", "X-Internal-Token")
	w := doPOST(h, map[string]string{"X-Internal-Token": "wrong"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestInternalTokenNetHTTPMissingHeader(t *testing.T) {
	h := newNetHTTPAdminHandler(t, "ADMIN_TOK_2", "correct-secret", "X-Internal-Token")
	w := doPOST(h, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestInternalTokenNetHTTPEnvNotSetPanics(t *testing.T) {
	t.Setenv("ADMIN_TOK_3", "")
	assert.Panics(t, func() {
		WrapInternalTokenNetHTTP(http.NotFoundHandler(), InternalTokenConfig{
			HeaderName:  "X-Internal-Token",
			TokenEnvVar: "ADMIN_TOK_3",
		})
	})
}

func TestInternalTokenNetHTTPNilNextPanics(t *testing.T) {
	t.Setenv("ADMIN_TOK_4", "abc")
	assert.Panics(t, func() {
		WrapInternalTokenNetHTTP(nil, InternalTokenConfig{
			HeaderName:  "X-Internal-Token",
			TokenEnvVar: "ADMIN_TOK_4",
		})
	})
}
