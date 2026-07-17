package octoauth

import (
	"context"
	"strings"
)

// botEndpoint is the octo-server route for bot-token verification. It never
// takes include=context — the response is already space-authoritative.
const botEndpoint = "/v1/auth/verify-bot"

// botResponse mirrors the JSON body returned by POST /v1/auth/verify-bot.
//
// SpaceID is required — an empty SpaceID collapses back to
// [ErrKindInvalidCredential].
type botResponse struct {
	BotUID    string `json:"bot_uid"`
	BotName   string `json:"bot_name"`
	Role      string `json:"role"`
	OwnerUID  string `json:"owner_uid"`
	OwnerName string `json:"owner_name"`
	SpaceID   string `json:"space_id"`
}

// botTokenVerifier resolves bot tokens (bf_-prefixed). The app_ prefix is
// reserved for a future App Bot token realm and is currently short-circuited
// to [ErrKindInvalidCredential] without any HTTP call — the classification
// hook remains so v2 can add support additively.
//
// The zero value is not usable; construct via [NewBotTokenVerifier].
type botTokenVerifier struct {
	cfg *Config
}

// NewBotTokenVerifier builds a [Verifier] for bot tokens. cfg is patched in
// place with defaults and MUST NOT be nil.
func NewBotTokenVerifier(cfg *Config) Verifier {
	applyDefaults(cfg)
	return &botTokenVerifier{cfg: cfg}
}

// Kind implements [Verifier].
func (v *botTokenVerifier) Kind() PrincipalKind { return KindBot }

// Verify implements [Verifier]. It short-circuits on empty and app_-prefixed
// credentials, checks the shared cache under the "b:" prefix, and calls
// POST /v1/auth/verify-bot. include=context is never sent for this realm.
func (v *botTokenVerifier) Verify(ctx context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "empty credential",
			Verifier: KindBot,
		}
	}
	// v1: reject app_ before touching the network so we do not create a
	// dependency the server does not yet support. The dispatch hook in
	// classifyCredential still routes app_ here so a future SDK release can
	// add support without a client-side breakage.
	if strings.HasPrefix(credential, PrefixApp) {
		return nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "app_ tokens are reserved and not supported in this SDK version",
			Verifier: KindBot,
		}
	}
	vc := newVerifyContext(v.cfg, KindBot, "b:", credential, v.cfg.BotTTL)
	if p, err, hit := vc.lookupCache(ctx); hit {
		return vc.recordCacheHit(p, err)
	}
	vc.recordCacheMiss()

	body, err := doVerifyRequest(ctx, v.cfg, botEndpoint, map[string]string{"bot_token": credential}, KindBot)
	if err != nil {
		return vc.finalize(ctx, nil, err)
	}
	var resp botResponse
	if decodeErr := decodeVerifyResponse(body, &resp, KindBot); decodeErr != nil {
		return vc.finalize(ctx, nil, decodeErr)
	}
	if resp.BotUID == "" || resp.SpaceID == "" {
		return vc.finalize(ctx, nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "verify-bot response missing uid or space_id",
			Verifier: KindBot,
		})
	}

	p := &Principal{
		Kind:        KindBot,
		UID:         resp.BotUID,
		Name:        resp.BotName,
		Role:        resp.Role,
		SpaceID:     resp.SpaceID,
		OwnerUID:    resp.OwnerUID,
		OwnerName:   resp.OwnerName,
		RelatedUIDs: []string{resp.BotUID},
		Context:     PrincipalContext{Kind: ContextNotRequested},
	}
	return vc.finalize(ctx, p, nil)
}
