// Package gin provides an octo-auth middleware for the gin-gonic/gin router.
//
// Typical use:
//
//	verifier := octoauth.NewFullMultiVerifier(cfg)
//	engine.Use(ginmw.New(ginmw.Options{
//	    Verifier:    verifier,
//	    SpaceHeader: "X-Space-Id",
//	}))
//	engine.GET("/hello", func(c *gin.Context) {
//	    p := ginmw.Principal(c)
//	    c.JSON(200, gin.H{"uid": p.UID})
//	})
package gin

import (
	"github.com/gin-gonic/gin"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
	"github.com/Mininglamp-OSS/octo-auth/go/middleware/internal/enrich"
)

// ctxKeyPrincipal is the string key used by [New] / [Principal] to shuttle
// the resolved Principal through gin's per-request key/value bag. Kept
// unexported so callers must go through [Principal] and cannot accidentally
// read a shared-type key.
const ctxKeyPrincipal = "octoauth.principal"

// Options configures the middleware returned by [New].
type Options struct {
	// Verifier is the credential verifier (single-realm or MultiVerifier).
	// Required.
	Verifier octoauth.Verifier
	// RequireKind, when non-empty, causes the middleware to reject any
	// credential whose classified [octoauth.PrincipalKind] does not match.
	// The rejection maps to [octoauth.ErrForbidden].
	RequireKind octoauth.PrincipalKind
	// SpaceHeader, when non-empty, enables the session-realm X-Space-Id
	// enrichment described in design doc §8.1. Leave empty to disable.
	SpaceHeader string
	// ErrorMapper, when non-nil, replaces [octoauth.DefaultErrorMapper]
	// for translating typed SDK errors to HTTP responses.
	ErrorMapper octoauth.ErrorMapperFunc
}

// New returns a gin middleware that extracts a credential from the request,
// verifies it against opts.Verifier, applies X-Space-Id enrichment, and
// stashes the resolved *[octoauth.Principal] under a private key. Downstream
// handlers pull it back via [Principal].
//
// Every request that reaches the middleware gets a fresh
// [octoauth.Principal.Clone] before enrichment mutates SpaceID, so the
// cache-shared *Principal returned by the verifier is never modified in
// place.
//
// New panics if opts.Verifier is nil — misconfiguration must fail at server
// startup, not the first request.
func New(opts Options) gin.HandlerFunc {
	if opts.Verifier == nil {
		panic("octoauth/middleware/gin: Options.Verifier is required")
	}
	mapper := opts.ErrorMapper
	if mapper == nil {
		mapper = octoauth.DefaultErrorMapper
	}
	return func(c *gin.Context) {
		cred, err := octoauth.ExtractCredential(c.Request)
		if err != nil {
			abort(c, mapper, err)
			return
		}
		if opts.RequireKind != "" && cred.Kind != opts.RequireKind {
			abort(c, mapper, &octoauth.Error{
				Kind:     octoauth.ErrKindForbidden,
				Message:  "credential kind not permitted",
				Verifier: cred.Kind,
			})
			return
		}
		principal, err := opts.Verifier.Verify(c.Request.Context(), cred.Raw)
		if err != nil {
			abort(c, mapper, err)
			return
		}
		// Defensive clone before mutation so any cache-shared Principals stay clean.
		principal = principal.Clone()
		if err := enrich.SpaceFromHeader(principal, opts.SpaceHeader, c.GetHeader); err != nil {
			abort(c, mapper, err)
			return
		}
		c.Set(ctxKeyPrincipal, principal)
		c.Next()
	}
}

// Principal returns the resolved *[octoauth.Principal] for the current
// request, or nil if the middleware did not run.
func Principal(c *gin.Context) *octoauth.Principal {
	v, ok := c.Get(ctxKeyPrincipal)
	if !ok {
		return nil
	}
	p, _ := v.(*octoauth.Principal)
	return p
}

// abort writes the mapped error response and stops the handler chain.
func abort(c *gin.Context, mapper octoauth.ErrorMapperFunc, err error) {
	status, body := mapper(err)
	c.Data(status, "application/json", body)
	c.Abort()
}
