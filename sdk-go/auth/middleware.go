package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/Mininglamp-OSS/octo-auth/sdk-go/contract"
)

// Prefixes for client-side token-kind detection. Matches the strict
// validation octo-server expects.
const (
	prefixBotFather = "bf_"
	prefixAppBot    = "app_"
	prefixAPIKey    = "uk_"

	// minBotTokenLen / minAPIKeyLen are SDK-side cheap rejections so a
	// malformed token doesn't waste a round-trip to octo-server. Values
	// align with octo-fleet's existing strict validation.
	minBotTokenLen = 3 + 16 // bf_/app_ + 16 chars
	minAPIKeyLen   = 3 + 32 // uk_ + 32 chars
)

// Middleware returns a Gin middleware that authenticates incoming
// requests against octo-server and injects the resulting identity into
// the request context. scope gates which token kinds the route accepts;
// a mismatch produces 403 AUTH_KIND_MISMATCH.
//
// Token extraction priority:
//  1. Authorization: Bearer <...> (the preferred form)
//  2. Custom `token:` header (legacy form preserved permanently for
//     octo-web / octo-ios / octo-android — see project doc §14.3)
//
// X-Space-Id header (if present) is injected into the context. The
// RequireSpaceMember decorator handles fail-closed checking.
func (c *Client) Middleware(scope Scope) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token, kind, ok := extractToken(ctx)
		if !ok {
			c.writeError(ctx, ErrTokenMissing)
			return
		}
		if !scope.allows(kind) {
			c.log.Warn("octoauth: kind mismatch", "scope", scope.String(), "kind", kind)
			c.writeError(ctx, ErrKindMismatch)
			return
		}

		// Validate prefix length client-side to dodge a round-trip on
		// obvious garbage.
		switch kind {
		case AuthKindBot:
			if len(token) < minBotTokenLen {
				c.writeError(ctx, ErrTokenInvalid)
				return
			}
		case AuthKindAPIKey:
			if len(token) < minAPIKeyLen {
				c.writeError(ctx, ErrTokenInvalid)
				return
			}
		}

		switch kind {
		case AuthKindSession:
			resp, err := c.VerifyUser(ctx.Request.Context(), token, true /* includeContext */)
			if err != nil {
				c.writeError(ctx, err)
				return
			}
			injectUserContext(ctx, resp)
		case AuthKindBot:
			resp, err := c.VerifyBot(ctx.Request.Context(), token)
			if err != nil {
				c.writeError(ctx, err)
				return
			}
			injectBotContext(ctx, resp)
		case AuthKindAPIKey:
			resp, err := c.VerifyAPIKey(ctx.Request.Context(), token, true /* includeContext */)
			if err != nil {
				c.writeError(ctx, err)
				return
			}
			injectAPIKeyContext(ctx, resp)
		}

		// Carry X-Space-Id forward (RequireSpaceMember does fail-closed
		// validation against verified spaces). Critical: do NOT
		// overwrite a server-verified bot/apikey binding with the
		// client-supplied header — yujiawei review on octo-auth#2
		// flagged this as a P0 cross-space exposure.
		//
		// Scope of the guard: only when the binding is *authoritative*,
		// not when CtxKeySpaceID was set as a display hint. Per the
		// contract (auth-v1.yaml VerifyBotResp.space_id):
		//   - User Bots: space_id is a display hint (first active
		//     space_member row). The bot owner may legitimately want
		//     X-Space-Id to route across the owner's other spaces, so
		//     the header MUST be allowed to override the hint.
		//   - App Bots Scope="space": space_id IS the binding; the
		//     header must NOT override (the verify-context-included
		//     branch in injectBotContext also sets verified-spaces so
		//     RequireSpaceMember enforces).
		//   - App Bots Scope="platform": no binding; header is fine.
		//   - API Keys: SpaceID is the binding.
		//
		// We disambiguate via CtxKeyContextIncluded — only the
		// authoritative paths set it (sessions ContextIncluded=true,
		// App Bots Scope=space, API Keys ContextIncluded=true).
		// OctoBoooot delta review on octo-auth#2 (577175c) caught the
		// User Bot regression when this guard fired unconditionally.
		if sp := ctx.GetHeader("X-Space-Id"); sp != "" {
			authoritative := false
			if v, ok := ctx.Get(CtxKeyContextIncluded); ok {
				if b, ok := v.(bool); ok && b {
					authoritative = true
				}
			}
			existing, ok := ctx.Get(CtxKeySpaceID)
			if !authoritative || !ok || existing == "" {
				ctx.Set(CtxKeySpaceID, sp)
			}
		}

		ctx.Next()
	}
}

// RequireSpaceMember is a Gin decorator that fails-closed if X-Space-Id
// is not in the verified spaces[] list. When the verify response did
// NOT include context (octo-server pre-v1 / opt-out), the decorator
// passes with a metric increment so the upgrade window is observable.
//
// Bot principals: VerifyBotResp does not carry context_included or
// spaces[], but the server-verified space binding (resp.SpaceID for
// scope=space bots) IS authoritative. injectBotContext sets
// CtxKeyContextIncluded=true + CtxKeyVerifiedSpaces=[r.SpaceID] for
// space-scoped bots so this decorator enforces against the bot's
// binding. Platform-scope bots (Scope="platform") do not set the
// context flag — they can access any space the caller explicitly
// targets, mirroring the legacy "no binding" semantic.
//
// yujiawei P0 review on octo-auth#2 flagged the original revision as
// a silent no-op for all bot principals; this version enforces.
func (c *Client) RequireSpaceMember() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		sp := ctx.GetHeader("X-Space-Id")
		if sp == "" {
			// No header to check — let the route's own handler decide.
			ctx.Next()
			return
		}
		if !IsContextIncluded(ctx) {
			// Pre-context-aware verify response. Log a metric for the
			// compatibility window; pass.
			c.col.ObserveSpaceUnverified()
			ctx.Next()
			return
		}
		for _, s := range GetVerifiedSpaces(ctx) {
			if s == sp {
				ctx.Next()
				return
			}
		}
		c.writeError(ctx, ErrSpaceForbidden)
	}
}

// RequireOwner returns a Gin decorator that 403s unless the verified
// principal's LoginUID matches the result of the supplied extractor
// (which typically reads a path parameter or query string for the
// claimed-owner UID).
func (c *Client) RequireOwner(extractor func(*gin.Context) string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		want := extractor(ctx)
		if want == "" || GetLoginUID(ctx) != want {
			c.writeError(ctx, ErrSpaceForbidden) // reuse code; semantic close enough
			return
		}
		ctx.Next()
	}
}

// extractToken pulls (token, kind, ok) from the incoming request. See
// Middleware docstring for the priority rules.
func extractToken(ctx *gin.Context) (string, AuthKind, bool) {
	if h := ctx.GetHeader("Authorization"); h != "" {
		const bearer = "Bearer "
		if strings.HasPrefix(h, bearer) {
			tok := strings.TrimSpace(h[len(bearer):])
			if tok == "" {
				return "", AuthKindUnknown, false
			}
			return tok, kindFromPrefix(tok), true
		}
	}
	// Fallback: legacy custom `token:` header used by octo-web / iOS /
	// Android. Per project doc §14.3 this fallback is a permanent
	// compatibility invariant — never remove without a coordinated
	// client-side migration to Bearer.
	if h := ctx.GetHeader("token"); h != "" {
		tok := strings.TrimSpace(h)
		return tok, kindFromPrefix(tok), true
	}
	return "", AuthKindUnknown, false
}

// kindFromPrefix classifies a raw token by prefix. Anything not
// matching uk_ or bf_/app_ is treated as a user session token (matches
// octo-server's legacy unprefixed user-token handling).
func kindFromPrefix(token string) AuthKind {
	switch {
	case strings.HasPrefix(token, prefixAPIKey):
		return AuthKindAPIKey
	case strings.HasPrefix(token, prefixBotFather), strings.HasPrefix(token, prefixAppBot):
		return AuthKindBot
	default:
		return AuthKindSession
	}
}

// writeError aborts the request with the SDK-side mapping of the
// sentinel error to (HTTP status, ErrorEnvelope.code).
func (c *Client) writeError(ctx *gin.Context, err error) {
	code := CodeTokenInvalid
	status := http.StatusUnauthorized
	switch {
	case errors.Is(err, ErrTokenMissing):
		code = CodeTokenMissing
	case errors.Is(err, ErrKindMismatch):
		code = CodeKindMismatch
		status = http.StatusForbidden
	case errors.Is(err, ErrSpaceForbidden):
		code = CodeSpaceForbidden
		status = http.StatusForbidden
	case errors.Is(err, ErrBotUnavailable):
		code = CodeBotUnavailable
		status = http.StatusServiceUnavailable
	case errors.Is(err, ErrUpstreamUnavailable):
		code = CodeUpstreamUnavailable
		status = http.StatusServiceUnavailable
	}
	ctx.AbortWithStatusJSON(status, contract.ErrorEnvelope{
		SchemaVersion: 1,
		Error:         contract.Error{Code: code, Message: err.Error(), HTTPStatus: status},
	})
}

// injectUserContext populates the SDK context keys from a VerifyUserResp.
func injectUserContext(ctx *gin.Context, r *contract.VerifyUserResp) {
	ctx.Set(CtxKeyLoginUID, r.UID)
	ctx.Set(CtxKeyName, r.Name)
	ctx.Set(CtxKeyRole, r.Role)
	ctx.Set(CtxKeyAuthKind, AuthKindSession)
	if r.Language != "" {
		ctx.Set(CtxKeyLanguage, r.Language)
	}
	if r.ContextIncluded {
		ctx.Set(CtxKeyContextIncluded, true)
		ctx.Set(CtxKeyVerifiedSpaces, r.Spaces)
		ctx.Set(CtxKeyOwnedBotsBySpace, r.OwnedBotsBySpace)
	}
	// related_uids = [self, owned_bots...]
	rel := []string{r.UID}
	for _, b := range r.OwnedBots {
		rel = append(rel, b.UID)
	}
	ctx.Set(CtxKeyRelatedUIDs, rel)
}

func injectBotContext(ctx *gin.Context, r *contract.VerifyBotResp) {
	ctx.Set(CtxKeyLoginUID, r.BotUID)
	ctx.Set(CtxKeyName, r.BotName)
	ctx.Set(CtxKeyAuthKind, AuthKindBot)
	ctx.Set(CtxKeyBotKind, r.BotKind)
	ctx.Set(CtxKeyOwnerUID, r.OwnerUID)
	if r.OwnerName != "" {
		ctx.Set(CtxKeyOwnerName, r.OwnerName)
	}
	if r.Language != "" {
		ctx.Set(CtxKeyLanguage, r.Language)
	}
	if r.Scope != "" {
		ctx.Set(CtxKeyAppBotScope, r.Scope)
	}
	if r.SpaceID != "" {
		ctx.Set(CtxKeySpaceID, r.SpaceID)
	}
	// yujiawei P0 review on octo-auth#2: VerifyBotResp lacks a
	// ContextIncluded field, so RequireSpaceMember was a silent
	// no-op for all bot principals. For space-scoped bots
	// (Scope="space"), the server-verified SpaceID is the
	// authoritative binding — populate the same SDK-context keys
	// the user path uses so RequireSpaceMember enforces against
	// {r.SpaceID} as the only allowed space.
	//
	// OctoBoooot round-4 P0 (carried into round-5): if octo-server
	// returns Scope="space" but SpaceID="" (a contract violation,
	// not a legal value), the prior revision only set the keys
	// inside the `if r.SpaceID != ""` outer guard, so a
	// contract-violating response left CtxKeyContextIncluded unset
	// and RequireSpaceMember fell into the compat-pass branch —
	// accepting any X-Space-Id. Fail closed here instead: set
	// CtxKeyContextIncluded=true with an empty verified-spaces list,
	// guaranteeing RequireSpaceMember 403s on any non-empty
	// X-Space-Id rather than silently allowing cross-space access.
	// Platform-scope bots are unaffected; they stay context-uncommitted.
	if r.Scope == "space" {
		ctx.Set(CtxKeyContextIncluded, true)
		if r.SpaceID != "" {
			ctx.Set(CtxKeyVerifiedSpaces, []string{r.SpaceID})
		} else {
			ctx.Set(CtxKeyVerifiedSpaces, []string{})
		}
	}
	// related_uids = [self, owner]
	rel := []string{r.BotUID}
	if r.OwnerUID != "" {
		rel = append(rel, r.OwnerUID)
	}
	ctx.Set(CtxKeyRelatedUIDs, rel)
}

func injectAPIKeyContext(ctx *gin.Context, r *contract.VerifyAPIKeyResp) {
	ctx.Set(CtxKeyLoginUID, r.UID)
	ctx.Set(CtxKeyAuthKind, AuthKindAPIKey)
	if r.SpaceID != "" {
		ctx.Set(CtxKeySpaceID, r.SpaceID)
	}
	if r.ContextIncluded {
		ctx.Set(CtxKeyContextIncluded, true)
		// Verified spaces = union(OwnedBotsBySpace keys, {r.SpaceID}).
		// Jerry-Xin round-4 P0 on octo-auth#2: the prior revision built
		// the set from OwnedBotsBySpace keys only, so an API key bound to
		// a single space with no owned bots
		// (context_included=true, space_id="sp_A", owned_bots_by_space={})
		// produced an empty verified-spaces list — RequireSpaceMember
		// then 403s a legitimate `X-Space-Id: sp_A` request. The bound
		// SpaceID IS an authoritative space membership signal, so it
		// must be in the verified set. Dedup defensively in case
		// OwnedBotsBySpace also lists the bound space.
		spaceSet := make(map[string]struct{}, len(r.OwnedBotsBySpace)+1)
		for k := range r.OwnedBotsBySpace {
			spaceSet[k] = struct{}{}
		}
		if r.SpaceID != "" {
			spaceSet[r.SpaceID] = struct{}{}
		}
		spaces := make([]string, 0, len(spaceSet))
		for k := range spaceSet {
			spaces = append(spaces, k)
		}
		ctx.Set(CtxKeyVerifiedSpaces, spaces)
		ctx.Set(CtxKeyOwnedBotsBySpace, r.OwnedBotsBySpace)
	}
}
