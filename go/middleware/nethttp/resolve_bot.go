package nethttp

import (
	"context"
	"net/http"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
)

type botResolvedKey struct{}

// BotResolveOptions binds a fixed mode and Action to a trusted route. The
// public caller can supply its credential and target Space, not the Action.
type BotResolveOptions struct {
	Resolver    octoauth.Resolver
	Mode        octoauth.BotResolveMode
	Action      string
	SpaceID     func(*http.Request) string
	ErrorMapper octoauth.ErrorMapperFunc
}

// WrapBotResolve performs a Bot Resolve before handing the request to next.
// OBO routes require obo=true; AS_BOT routes reject that marker, so a denial
// can never silently fall back to Bot-self access. The route's Action is
// immutable after middleware construction.
func WrapBotResolve(next http.Handler, opts BotResolveOptions) http.Handler {
	if opts.Resolver == nil {
		panic("octoauth/middleware/nethttp: BotResolveOptions.Resolver is required")
	}
	if opts.Mode != octoauth.ModeAsBot && opts.Mode != octoauth.ModeOBO {
		panic("octoauth/middleware/nethttp: invalid Bot Resolve mode")
	}
	if (opts.Mode == octoauth.ModeOBO) != (opts.Action != "") {
		panic("octoauth/middleware/nethttp: Action must be fixed for OBO only")
	}
	spaceID := opts.SpaceID
	if spaceID == nil {
		spaceID = func(r *http.Request) string { return r.URL.Query().Get("space_id") }
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
		if cred.Kind != octoauth.KindBot {
			write(w, mapper, &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential, Message: "Bot credential required"})
			return
		}
		marker := r.URL.Query().Get("obo")
		if (opts.Mode == octoauth.ModeOBO && marker != "true") || (opts.Mode == octoauth.ModeAsBot && marker != "") {
			write(w, mapper, &octoauth.Error{Kind: octoauth.ErrKindInvalidRequest, Message: "OBO marker does not match route mode"})
			return
		}
		for _, forbidden := range []string{"on_behalf_of", "human_uid", "subject_uid"} {
			if r.URL.Query().Has(forbidden) {
				write(w, mapper, &octoauth.Error{Kind: octoauth.ErrKindInvalidRequest, Message: "Subject cannot be selected by caller"})
				return
			}
		}
		principal, err := opts.Resolver.Resolve(r.Context(), cred.Raw, octoauth.ResolveRequest{
			Mode: opts.Mode, SpaceID: spaceID(r), Action: opts.Action,
		})
		if err != nil {
			write(w, mapper, err)
			return
		}
		ctx := context.WithValue(r.Context(), botResolvedKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// BotResolvedPrincipal returns the dual-identity result set by WrapBotResolve.
func BotResolvedPrincipal(ctx context.Context) *octoauth.ResolvedPrincipal {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(botResolvedKey{}).(*octoauth.ResolvedPrincipal)
	return p
}
