// Package nethttp provides an octo-auth middleware for the standard library
// net/http router.
//
// Typical use:
//
//	verifier := octoauth.NewFullMultiVerifier(cfg)
//	handler := nethttpmw.Wrap(myHandler, nethttpmw.Options{
//	    Verifier:    verifier,
//	    SpaceHeader: "X-Space-Id",
//	})
//	http.ListenAndServe(":8080", handler)
//
// Inside myHandler, the resolved principal is retrieved from the request
// context via [Principal](r.Context()).
package nethttp

import (
	"context"
	"net/http"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
	"github.com/Mininglamp-OSS/octo-auth/go/middleware/internal/enrich"
)

// ctxKey is the private context.Value key type used to shuttle Principals
// through the request context. Using an unexported type prevents collisions
// with third-party middleware that might use string keys.
type ctxKey struct{}

var principalKey = ctxKey{}

// Options configures the middleware returned by [Wrap]. Fields mirror the
// other middleware packages for API parity.
type Options struct {
	Verifier    octoauth.Verifier
	RequireKind octoauth.PrincipalKind
	SpaceHeader string
	ErrorMapper octoauth.ErrorMapperFunc
}

// Wrap returns an http.Handler that runs the auth middleware in front of
// next. See the gin package docstring for detailed semantics; the only
// difference here is that the resolved Principal is stored in the request
// context and pulled back via [Principal].
//
// Wrap panics if opts.Verifier is nil.
func Wrap(next http.Handler, opts Options) http.Handler {
	if opts.Verifier == nil {
		panic("octoauth/middleware/nethttp: Options.Verifier is required")
	}
	mapper := opts.ErrorMapper
	if mapper == nil {
		mapper = octoauth.DefaultErrorMapper
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, err := octoauth.ExtractCredential(r)
		if err != nil {
			write(w, mapper, err)
			return
		}
		if opts.RequireKind != "" && cred.Kind != opts.RequireKind {
			write(w, mapper, &octoauth.Error{
				Kind:     octoauth.ErrKindForbidden,
				Message:  "credential kind not permitted",
				Verifier: cred.Kind,
			})
			return
		}
		principal, err := opts.Verifier.Verify(r.Context(), cred.Raw)
		if err != nil {
			write(w, mapper, err)
			return
		}
		principal = principal.Clone()
		if err := enrich.SpaceFromHeader(principal, opts.SpaceHeader, r.Header.Get); err != nil {
			write(w, mapper, err)
			return
		}
		ctx := context.WithValue(r.Context(), principalKey, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Principal returns the resolved *[octoauth.Principal] attached to ctx by
// [Wrap], or nil when the middleware did not run.
func Principal(ctx context.Context) *octoauth.Principal {
	if ctx == nil {
		return nil
	}
	v := ctx.Value(principalKey)
	if v == nil {
		return nil
	}
	p, _ := v.(*octoauth.Principal)
	return p
}

// write emits the mapped status + body with a JSON Content-Type header.
func write(w http.ResponseWriter, mapper octoauth.ErrorMapperFunc, err error) {
	status, body := mapper(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
