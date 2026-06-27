// Package auth is the Go SDK for octo-auth/contract/auth-v1.yaml.
//
// Service authors integrate it as a Gin middleware that authenticates
// requests against octo-server's /v1/auth/verify* endpoints, with a
// SHA-256-keyed LRU cache so the hot path doesn't round-trip on every
// request.
//
// Minimal usage:
//
//	client, err := auth.New(auth.Options{ServerURL: "https://octo-server"})
//	if err != nil { ... }
//
//	r := gin.Default()
//	r.Use(client.Middleware(auth.ScopeAny))
//	r.GET("/v1/things", func(c *gin.Context) {
//	    uid := auth.GetLoginUID(c)
//	    // ...
//	})
//
// Cache keys are always SHA-256(kind + ":" + token) — the raw token
// never leaves the request goroutine. Cache TTL bounds revocation
// windows; the default (60s) matches what octo-matter and octo-fleet
// have been using and is exposed via Options.CacheTTL.
//
// On octo-server 5xx, the middleware fails CLOSED — no stale-cache
// fallback. The rationale: a stale-cache fallback would extend the
// revocation window indefinitely under upstream flapping, which is a
// security hazard. Brief outages should be handled with retry, not
// stale auth.
package auth
