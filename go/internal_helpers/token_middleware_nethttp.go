package internalhelpers

import (
	"log/slog"
	"net/http"
)

// WrapInternalTokenNetHTTP wraps next with an internal-token check that
// mirrors [NewInternalTokenGinMiddleware]. Failed checks respond with 401
// and a byte-identical body; successful checks call through to next.
//
// Panics if cfg is misconfigured.
func WrapInternalTokenNetHTTP(next http.Handler, cfg InternalTokenConfig) http.Handler {
	r := resolveInternalTokenConfig(cfg, "octoauth/internal_helpers.WrapInternalTokenNetHTTP")
	if next == nil {
		panic("octoauth/internal_helpers.WrapInternalTokenNetHTTP: next handler is required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		got := req.Header.Get(r.headerName)
		if !constantTimeEqualString(got, r.tokenBytes) {
			r.logger.Debug("octoauth/internal_helpers: internal token check failed",
				slog.String("header", r.headerName),
				slog.String("token_hint", r.tokenHint),
				slog.Bool("header_present", got != ""),
			)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(internalTokenUnauthorizedBody)
			return
		}
		next.ServeHTTP(w, req)
	})
}
