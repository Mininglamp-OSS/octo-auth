// Package wkhttp provides an octo-auth middleware for the wkhttp router
// (github.com/WuKongIM/WuKongIM/pkg/wkhttp), which is a thin wrapper over
// gin used by octo-fleet and octo-matter.
//
// Typical use:
//
//	verifier := octoauth.NewFullMultiVerifier(cfg)
//	app := wkhttp.New()
//	app.Use(wkhttpmw.New(wkhttpmw.Options{
//	    Verifier:    verifier,
//	    SpaceHeader: "X-Space-Id",
//	}))
//	app.GET("/hello", func(c *wkhttp.Context) {
//	    p := wkhttpmw.Principal(c)
//	    c.JSON(200, map[string]string{"uid": p.UID})
//	})
package wkhttp

import (
	"github.com/WuKongIM/WuKongIM/pkg/wkhttp"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
	"github.com/Mininglamp-OSS/octo-auth/go/middleware/internal/enrich"
)

// ctxKeyPrincipal is the gin.Context key wkhttp inherits. Kept unexported
// so callers must go through [Principal].
const ctxKeyPrincipal = "octoauth.principal"

// Options configures the middleware returned by [New]. Fields mirror the
// gin package for API parity.
type Options struct {
	Verifier    octoauth.Verifier
	RequireKind octoauth.PrincipalKind
	SpaceHeader string
	ErrorMapper octoauth.ErrorMapperFunc
}

// New returns a wkhttp middleware. Because wkhttp.Context embeds
// *gin.Context, the implementation reuses gin's abort / header / next
// primitives directly.
//
// New panics if opts.Verifier is nil.
func New(opts Options) wkhttp.HandlerFunc {
	if opts.Verifier == nil {
		panic("octoauth/middleware/wkhttp: Options.Verifier is required")
	}
	mapper := opts.ErrorMapper
	if mapper == nil {
		mapper = octoauth.DefaultErrorMapper
	}
	return func(c *wkhttp.Context) {
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
func Principal(c *wkhttp.Context) *octoauth.Principal {
	v, ok := c.Get(ctxKeyPrincipal)
	if !ok {
		return nil
	}
	p, _ := v.(*octoauth.Principal)
	return p
}

// abort writes the mapped error response and stops the handler chain.
func abort(c *wkhttp.Context, mapper octoauth.ErrorMapperFunc, err error) {
	status, body := mapper(err)
	c.Data(status, "application/json", body)
	c.Abort()
}
