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
		// validation against verified spaces).
		if sp := ctx.GetHeader("X-Space-Id"); sp != "" {
			ctx.Set(CtxKeySpaceID, sp)
		}

		ctx.Next()
	}
}

// RequireSpaceMember is a Gin decorator that fails-closed if X-Space-Id
// is not in the verified spaces[] list. When the verify response did
// NOT include context (octo-server pre-v1 / opt-out), the decorator
// passes with a metric increment so the upgrade window is observable.
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
		// API key context only exposes per-space owned bots; the
		// verified-spaces list is the set of keys.
		spaces := make([]string, 0, len(r.OwnedBotsBySpace))
		for k := range r.OwnedBotsBySpace {
			spaces = append(spaces, k)
		}
		ctx.Set(CtxKeyVerifiedSpaces, spaces)
		ctx.Set(CtxKeyOwnedBotsBySpace, r.OwnedBotsBySpace)
	}
}
