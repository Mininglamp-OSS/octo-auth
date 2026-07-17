package internalhelpers

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// InternalTokenConfig configures the internal-token middleware factories.
//
// Required fields:
//   - HeaderName:  the request header that carries the shared secret,
//     e.g. "X-Runtime-Admin-Token" (fleet) or "X-Internal-Token" (server).
//   - TokenEnvVar: the process env var that stores the expected shared
//     secret value, e.g. "OCTO_RUNTIME_ADMIN_TOKEN".
//
// Optional fields:
//   - Logger: slog handle for diagnostics (default slog.Default()).
type InternalTokenConfig struct {
	HeaderName  string
	TokenEnvVar string
	Logger      *slog.Logger
}

// resolvedInternalTokenConfig is the validated + env-loaded snapshot used
// by both the gin and net/http factories. Building it once at middleware-
// construction time keeps the request hot path free of env lookups and
// gives us the fail-fast behavior the design expects.
type resolvedInternalTokenConfig struct {
	headerName string
	tokenBytes []byte
	logger     *slog.Logger
	tokenHint  string
}

// resolveInternalTokenConfig validates cfg and reads the token from the
// process env. Panics on misconfiguration (missing HeaderName / TokenEnvVar
// / env var empty) so the middleware fails at server startup rather than
// silently degrading.
func resolveInternalTokenConfig(cfg InternalTokenConfig, source string) resolvedInternalTokenConfig {
	if cfg.HeaderName == "" {
		panic(source + ": InternalTokenConfig.HeaderName is required")
	}
	if cfg.TokenEnvVar == "" {
		panic(source + ": InternalTokenConfig.TokenEnvVar is required")
	}
	token := os.Getenv(cfg.TokenEnvVar)
	if token == "" {
		panic(fmt.Sprintf("%s: env var %q is empty (fail-closed)", source, cfg.TokenEnvVar))
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return resolvedInternalTokenConfig{
		headerName: cfg.HeaderName,
		tokenBytes: []byte(token),
		logger:     logger,
		tokenHint:  maskToken(token),
	}
}

// internalTokenUnauthorizedBody is the byte-identical reject response used
// by both middleware flavors. Keeping it as a package-level constant guards
// against accidental per-flavor drift and matches the anti-enumeration
// pattern from [octoauth.DefaultErrorMapper].
var internalTokenUnauthorizedBody = []byte(`{"error":"unauthorized"}`)

// NewInternalTokenGinMiddleware returns a gin middleware that validates the
// configured header against the environment-provided shared secret using
// [subtle.ConstantTimeCompare]. Failed checks respond with 401 and a
// byte-identical body regardless of whether the header was missing, empty,
// or wrong.
//
// Panics if cfg is misconfigured (see [resolveInternalTokenConfig]).
func NewInternalTokenGinMiddleware(cfg InternalTokenConfig) gin.HandlerFunc {
	r := resolveInternalTokenConfig(cfg, "octoauth/internal_helpers.NewInternalTokenGinMiddleware")
	return func(c *gin.Context) {
		got := c.GetHeader(r.headerName)
		if !constantTimeEqualString(got, r.tokenBytes) {
			r.logger.Debug("octoauth/internal_helpers: internal token check failed",
				slog.String("header", r.headerName),
				slog.String("token_hint", r.tokenHint),
				slog.Bool("header_present", got != ""),
			)
			c.Data(http.StatusUnauthorized, "application/json", internalTokenUnauthorizedBody)
			c.Abort()
			return
		}
		c.Next()
	}
}

// constantTimeEqualString compares got (untrusted, arbitrary length) with
// want (trusted secret bytes) in constant time relative to want's length.
//
// A plain [subtle.ConstantTimeCompare] short-circuits when the two inputs
// have different lengths — that itself leaks the secret's length to an
// attacker sending short probes. We work around this by always comparing
// against a padded-out buffer the same length as want.
func constantTimeEqualString(got string, want []byte) bool {
	if len(got) == 0 {
		return false
	}
	if len(got) != len(want) {
		// Still burn ~O(len(want)) time so an attacker cannot use timing
		// to distinguish "wrong length" from "wrong content".
		junk := make([]byte, len(want))
		_ = subtle.ConstantTimeCompare(junk, want)
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), want) == 1
}
