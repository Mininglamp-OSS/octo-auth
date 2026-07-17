package octoauth

import (
	"context"
)

// sessionEndpoint is the octo-server route for human-session verification.
// The include=context query is appended conditionally at request time.
const sessionEndpoint = "/v1/auth/verify"

// OwnedBot is one entry of the session response's owned_bots array.
// Mirrors server-side `ownedBot` in modules/user/api.go.
type OwnedBot struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
}

// sessionResponse mirrors the JSON body returned by
// POST /v1/auth/verify(?include=context).
//
// context_included is *bool so a missing field (pre-v2 server, or v2+
// server that declined this call — server v3 emits with omitempty so
// the two are indistinguishable on the wire) is distinguishable from
// an explicit false at decode time. See design doc §2.2.
type sessionResponse struct {
	UID              string              `json:"uid"`
	Name             string              `json:"name"`
	Role             string              `json:"role"`
	OwnedBots        []OwnedBot          `json:"owned_bots"`
	ContextIncluded  *bool               `json:"context_included"`
	Spaces           []string            `json:"spaces"`
	OwnedBotsBySpace map[string][]string `json:"owned_bots_by_space"`
}

// sessionVerifier resolves human-session tokens (32-hex UUIDs, no prefix).
// The zero value is not usable; construct via [NewSessionVerifier].
type sessionVerifier struct {
	cfg *Config
}

// NewSessionVerifier builds a [Verifier] that resolves session tokens against
// octo-server. cfg is patched in place with defaults; it MUST NOT be nil.
//
// Callers who want the three verifiers to share a cache pass the same *Config
// to each constructor; [applyDefaults] is idempotent and installs a single
// LRU on the first call.
func NewSessionVerifier(cfg *Config) Verifier {
	applyDefaults(cfg)
	return &sessionVerifier{cfg: cfg}
}

// Kind implements [Verifier].
func (v *sessionVerifier) Kind() PrincipalKind { return KindSession }

// Verify implements [Verifier]. It short-circuits empty credentials, checks
// the shared cache under the "s:" prefix, and issues a POST /v1/auth/verify
// with an optional ?include=context query controlled by
// [Config.RequestIncludeContext].
func (v *sessionVerifier) Verify(ctx context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "empty credential",
			Verifier: KindSession,
		}
	}
	vc := newVerifyContext(v.cfg, KindSession, "s:", credential, v.cfg.SessionTTL)
	if p, err, hit := vc.lookupCache(ctx); hit {
		return vc.recordCacheHit(p, err)
	}
	vc.recordCacheMiss()

	endpoint := sessionEndpoint
	includeCtx := v.cfg.RequestIncludeContext != nil && *v.cfg.RequestIncludeContext
	if includeCtx {
		endpoint += "?include=context"
	}
	body, err := doVerifyRequest(ctx, v.cfg, endpoint, map[string]string{"token": credential}, KindSession)
	if err != nil {
		return vc.finalize(ctx, nil, err)
	}

	var resp sessionResponse
	if decodeErr := decodeVerifyResponse(body, &resp, KindSession); decodeErr != nil {
		return vc.finalize(ctx, nil, decodeErr)
	}
	if resp.UID == "" {
		return vc.finalize(ctx, nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "verify response missing uid",
			Verifier: KindSession,
		})
	}

	p := &Principal{
		Kind:        KindSession,
		UID:         resp.UID,
		Name:        resp.Name,
		Role:        resp.Role,
		RelatedUIDs: buildSessionRelated(resp.UID, resp.OwnedBots),
		Context:     sessionContextFromResponse(resp, includeCtx),
	}
	return vc.finalize(ctx, p, nil)
}

// buildSessionRelated returns [self, ...ownedBotUIDs] with duplicates dropped
// while preserving order. Design doc §2.2: RelatedUIDs for a session is the
// self UID followed by the owned bot UIDs, useful for space membership fan-out.
func buildSessionRelated(self string, ownedBots []OwnedBot) []string {
	out := make([]string, 0, 1+len(ownedBots))
	seen := make(map[string]struct{}, 1+len(ownedBots))
	out = append(out, self)
	seen[self] = struct{}{}
	for _, b := range ownedBots {
		if b.UID == "" {
			continue
		}
		if _, ok := seen[b.UID]; ok {
			continue
		}
		out = append(out, b.UID)
		seen[b.UID] = struct{}{}
	}
	return out
}

// sessionContextFromResponse maps the response's context_included +
// spaces + owned_bots_by_space fields into a [PrincipalContext].
//
// If include=context was not requested, the returned Kind is
// ContextNotRequested (nothing to interpret). Otherwise:
//   - context_included == nil (missing) → ContextUnknownServer
//     Ambiguous: server is either pre-v2, or v3+ that declined this call
//     (the omitempty tag on the server side erases explicit false).
//   - context_included == false        → ContextNotIncluded
//     Currently unreachable against server v3 (omitempty erases false);
//     preserved for a future server that drops omitempty.
//   - context_included == true         → ContextIncluded (fields copied)
func sessionContextFromResponse(resp sessionResponse, includeRequested bool) PrincipalContext {
	if !includeRequested {
		return PrincipalContext{Kind: ContextNotRequested}
	}
	switch {
	case resp.ContextIncluded == nil:
		return PrincipalContext{Kind: ContextUnknownServer}
	case !*resp.ContextIncluded:
		return PrincipalContext{Kind: ContextNotIncluded}
	default:
		return PrincipalContext{
			Kind:             ContextIncluded,
			Spaces:           resp.Spaces,
			OwnedBotsBySpace: resp.OwnedBotsBySpace,
		}
	}
}
