package octoauth

import (
	"context"
	"sort"
)

// apiKeyEndpoint is the octo-server route for user-api-key verification.
const apiKeyEndpoint = "/v1/auth/verify-api-key"

// apiKeyResponse mirrors the JSON body returned by
// POST /v1/auth/verify-api-key(?include=context).
type apiKeyResponse struct {
	UID             string              `json:"uid"`
	SpaceID         string              `json:"space_id"`
	ContextIncluded *bool               `json:"context_included"`
	OwnedBots       map[string][]string `json:"owned_bots"`
}

// userKeyVerifier resolves user API keys (uk_-prefixed, length >= 35). It
// short-circuits obviously malformed keys locally to shield octo-server from
// wave-attack traffic.
//
// The zero value is not usable; construct via [NewUserKeyVerifier].
type userKeyVerifier struct {
	cfg *Config
}

// NewUserKeyVerifier builds a [Verifier] for user API keys. cfg is patched in
// place with defaults and MUST NOT be nil.
func NewUserKeyVerifier(cfg *Config) Verifier {
	applyDefaults(cfg)
	return &userKeyVerifier{cfg: cfg}
}

// Kind implements [Verifier].
func (v *userKeyVerifier) Kind() PrincipalKind { return KindAPIKey }

// Verify implements [Verifier]. It short-circuits empty and too-short keys,
// checks the shared cache under the "k:" prefix, and calls
// POST /v1/auth/verify-api-key with an optional ?include=context query.
func (v *userKeyVerifier) Verify(ctx context.Context, credential string) (*Principal, error) {
	if credential == "" {
		return nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "empty credential",
			Verifier: KindAPIKey,
		}
	}
	if err := ValidateAPIKey(credential); err != nil {
		return nil, err
	}
	vc := newVerifyContext(v.cfg, KindAPIKey, "k:", credential, v.cfg.APIKeyTTL)
	if p, err, hit := vc.lookupCache(ctx); hit {
		return vc.recordCacheHit(p, err)
	}
	vc.recordCacheMiss()

	endpoint := apiKeyEndpoint
	includeCtx := v.cfg.RequestIncludeContext != nil && *v.cfg.RequestIncludeContext
	if includeCtx {
		endpoint += "?include=context"
	}
	body, err := doVerifyRequest(ctx, v.cfg, endpoint, map[string]string{"api_key": credential}, KindAPIKey)
	if err != nil {
		return vc.finalize(ctx, nil, err)
	}

	var resp apiKeyResponse
	if decodeErr := decodeVerifyResponse(body, &resp, KindAPIKey); decodeErr != nil {
		return vc.finalize(ctx, nil, decodeErr)
	}
	if resp.UID == "" || resp.SpaceID == "" {
		return vc.finalize(ctx, nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "verify-api-key response missing uid or space_id",
			Verifier: KindAPIKey,
		})
	}

	p := &Principal{
		Kind:    KindAPIKey,
		UID:     resp.UID,
		SpaceID: resp.SpaceID,
		Context: apiKeyContextFromResponse(resp, includeCtx),
	}
	return vc.finalize(ctx, p, nil)
}

// apiKeyContextFromResponse mirrors [sessionContextFromResponse] for the
// api-key realm. When context is included, Spaces is derived from the
// owned_bots map keys so downstream space-membership checks have a canonical
// list.
func apiKeyContextFromResponse(resp apiKeyResponse, includeRequested bool) PrincipalContext {
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
			Spaces:           spacesFromOwnedBots(resp.OwnedBots),
			OwnedBotsBySpace: resp.OwnedBots,
		}
	}
}

// spacesFromOwnedBots returns the sorted list of map keys. Sorting keeps the
// output deterministic across Go versions and across cache hits.
func spacesFromOwnedBots(owned map[string][]string) []string {
	if len(owned) == 0 {
		return nil
	}
	out := make([]string, 0, len(owned))
	for k := range owned {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
