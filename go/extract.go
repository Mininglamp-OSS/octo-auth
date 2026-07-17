package octoauth

import (
	"net/http"
	"strings"
)

// Header names and credential-prefix constants used across the SDK. Callers
// referring to these names in middleware or helpers should import the
// constants rather than hard-coding strings so a rename in the future stays
// in one place.
const (
	// HeaderAuthorization is the RFC 7235 authorization header.
	HeaderAuthorization = "Authorization"
	// HeaderToken is the octo-server-native token header used by some
	// clients (mirrors what octo-server itself accepts as a fallback).
	HeaderToken = "token"
	// BearerScheme is the (case-insensitive) prefix for bearer tokens.
	BearerScheme = "Bearer"

	// PrefixUK marks a userKeyVerifier credential.
	PrefixUK = "uk_"
	// PrefixBF marks a botTokenVerifier credential.
	PrefixBF = "bf_"
	// PrefixApp is reserved for the future App Bot token realm; v1 forwards
	// it to the bot verifier so a future rollout stays additive.
	PrefixApp = "app_"

	// MinAPIKeyLength is the minimum total length (including the "uk_"
	// prefix) that a user API key must have. Matches octo-fleet's
	// `len >= 35` guard and the design-doc §3 dispatch rule.
	MinAPIKeyLength = 35
)

// ExtractCredential pulls the credential from an HTTP request following the
// pattern shared by the 5 surveyed services: prefer Authorization: Bearer
// <token>, fall back to the raw "token" header. The returned [Credential] has
// its Kind populated by prefix inspection (session / bot / apikey).
//
// Returns [*Error] with Kind ErrKindInvalidCredential when no credential is
// present, when an Authorization header uses a non-bearer scheme with an
// empty token, or when a "uk_"-prefixed credential is shorter than
// [MinAPIKeyLength].
func ExtractCredential(r *http.Request) (Credential, error) {
	if r == nil {
		return Credential{}, &Error{
			Kind:    ErrKindInvalidCredential,
			Message: "nil request",
		}
	}
	raw := readCredentialHeader(r.Header)
	if raw == "" {
		return Credential{}, &Error{
			Kind:    ErrKindInvalidCredential,
			Message: "missing credential",
		}
	}
	kind, err := classifyCredential(raw)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Kind: kind, Raw: raw}, nil
}

// readCredentialHeader reads an Authorization: Bearer token (case-insensitive
// scheme) with fallback to the raw "token" header. Returns the trimmed token
// or "" if neither header carries one.
func readCredentialHeader(h http.Header) string {
	if auth := h.Get(HeaderAuthorization); auth != "" {
		if token := stripBearer(auth); token != "" {
			return token
		}
		// An Authorization header without a bearer token is treated the
		// same as no header at all — fall through to the "token" header
		// rather than erroring out, matching docs-backend's extractOctoToken
		// behavior.
	}
	if tok := strings.TrimSpace(h.Get(HeaderToken)); tok != "" {
		return tok
	}
	return ""
}

// stripBearer returns the token part of "Bearer <token>" (scheme match is
// case-insensitive per RFC 7235). Returns "" if the value is not a bearer
// credential.
func stripBearer(v string) string {
	trimmed := strings.TrimSpace(v)
	if len(trimmed) <= len(BearerScheme) {
		return ""
	}
	if !strings.EqualFold(trimmed[:len(BearerScheme)], BearerScheme) {
		return ""
	}
	rest := trimmed[len(BearerScheme):]
	// Scheme must be followed by whitespace per RFC 7235; be lenient and
	// accept any whitespace run.
	if len(rest) == 0 || (rest[0] != ' ' && rest[0] != '\t') {
		return ""
	}
	return strings.TrimSpace(rest)
}

// ValidateAPIKey checks that token has the "uk_" prefix and meets the length
// requirement. Returns nil on success or [*Error] Kind ErrKindInvalidCredential
// on failure. Useful for producers who mint their own keys and want to catch
// obvious mistakes before shipping them.
func ValidateAPIKey(token string) error {
	if !strings.HasPrefix(token, PrefixUK) {
		return &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "api key missing uk_ prefix",
			Verifier: KindAPIKey,
		}
	}
	if len(token) < MinAPIKeyLength {
		return &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "api key too short",
			Verifier: KindAPIKey,
		}
	}
	return nil
}

// ValidateBotToken checks that token has one of the bot-realm prefixes ("bf_"
// or the reserved "app_"). Returns nil on success or [*Error] on failure.
func ValidateBotToken(token string) error {
	if strings.HasPrefix(token, PrefixBF) || strings.HasPrefix(token, PrefixApp) {
		if len(token) <= len(PrefixBF) {
			return &Error{
				Kind:     ErrKindInvalidCredential,
				Message:  "bot token has prefix only",
				Verifier: KindBot,
			}
		}
		return nil
	}
	return &Error{
		Kind:     ErrKindInvalidCredential,
		Message:  "bot token missing bf_/app_ prefix",
		Verifier: KindBot,
	}
}
