// Package echo provides an octo-auth middleware for the labstack/echo router.
//
// Typical use:
//
//	verifier := octoauth.NewFullMultiVerifier(cfg)
//	e := echo.New()
//	e.Use(echomw.New(echomw.Options{
//	    Verifier:    verifier,
//	    SpaceHeader: "X-Space-Id",
//	}))
//	e.GET("/hello", func(c echo.Context) error {
//	    p := echomw.Principal(c)
//	    return c.JSON(200, map[string]string{"uid": p.UID})
//	})
package echo

import (
	"github.com/labstack/echo/v4"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
	"github.com/Mininglamp-OSS/octo-auth/go/middleware/internal/enrich"
)

// ctxKeyPrincipal is the private key echo.Context uses to shuttle the
// resolved Principal to downstream handlers.
const ctxKeyPrincipal = "octoauth.principal"

// Options configures the middleware returned by [New]. Fields mirror the
// gin package for API parity.
type Options struct {
	Verifier    octoauth.Verifier
	RequireKind octoauth.PrincipalKind
	SpaceHeader string
	ErrorMapper octoauth.ErrorMapperFunc
}

// New returns an echo middleware that extracts, verifies, and enriches the
// credential the same way the gin middleware does — see the gin package
// docstring for detailed semantics.
//
// New panics if opts.Verifier is nil.
func New(opts Options) echo.MiddlewareFunc {
	if opts.Verifier == nil {
		panic("octoauth/middleware/echo: Options.Verifier is required")
	}
	mapper := opts.ErrorMapper
	if mapper == nil {
		mapper = octoauth.DefaultErrorMapper
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cred, err := octoauth.ExtractCredential(c.Request())
			if err != nil {
				return respond(c, mapper, err)
			}
			if opts.RequireKind != "" && cred.Kind != opts.RequireKind {
				return respond(c, mapper, &octoauth.Error{
					Kind:     octoauth.ErrKindForbidden,
					Message:  "credential kind not permitted",
					Verifier: cred.Kind,
				})
			}
			principal, err := opts.Verifier.Verify(c.Request().Context(), cred.Raw)
			if err != nil {
				return respond(c, mapper, err)
			}
			principal = principal.Clone()
			if err := enrich.SpaceFromHeader(principal, opts.SpaceHeader, c.Request().Header.Get); err != nil {
				return respond(c, mapper, err)
			}
			c.Set(ctxKeyPrincipal, principal)
			return next(c)
		}
	}
}

// Principal returns the resolved *[octoauth.Principal] stashed on the echo
// context by [New], or nil if the middleware did not run.
func Principal(c echo.Context) *octoauth.Principal {
	v := c.Get(ctxKeyPrincipal)
	if v == nil {
		return nil
	}
	p, _ := v.(*octoauth.Principal)
	return p
}

// respond writes the mapped error body and returns nil so echo's default
// error handler does not overwrite it.
func respond(c echo.Context, mapper octoauth.ErrorMapperFunc, err error) error {
	status, body := mapper(err)
	return c.Blob(status, "application/json", body)
}
