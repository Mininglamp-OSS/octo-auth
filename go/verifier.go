// Package octoauth provides a client SDK to verify octo-server credentials.
//
// It exposes three verifier realms — session, bot, api-key — behind a unified
// [Verifier] interface, plus a [MultiVerifier] facade that dispatches to the
// correct realm based on the credential prefix.
//
// The SDK is designed as a thin, allocation-conscious wrapper over octo-server's
// verify endpoints, with a pluggable [Cache] and [MetricsCollector] and typed
// [Error] values to enable fail-closed middleware behavior.
package octoauth

import (
	"context"
	"fmt"
	"strings"
)

// PrincipalKind identifies which authentication realm produced a [Principal].
type PrincipalKind string

// The three supported realms. See design doc §2.1.
const (
	// KindSession denotes a human-session token (32-hex UUID, no prefix).
	KindSession PrincipalKind = "session"
	// KindBot denotes a bot token (bf_-prefixed; app_ reserved).
	KindBot PrincipalKind = "bot"
	// KindAPIKey denotes a user API key (uk_-prefixed, length >= 35).
	KindAPIKey PrincipalKind = "apikey"
)

// Principal is the resolved identity returned by a [Verifier].
//
// Field population depends on Kind:
//   - session: UID, Name, Role, RelatedUIDs (self + owned bots); SpaceID
//     requires X-Space-Id enrichment at the middleware layer.
//   - bot:     UID, Name, Role, SpaceID, OwnerUID, OwnerName, RelatedUIDs=[self].
//   - apikey:  UID, SpaceID; Name/Role empty, RelatedUIDs nil.
type Principal struct {
	Kind PrincipalKind

	UID       string
	Name      string
	Role      string
	SpaceID   string
	OwnerUID  string
	OwnerName string

	RelatedUIDs []string

	Context PrincipalContext
}

// PrincipalContext carries the optional include=context payload from octo-server
// v2+, plus a [ContextKind] flag that lets callers reason about pre-v2 servers
// without special-casing missing fields.
type PrincipalContext struct {
	Kind ContextKind

	Spaces           []string
	OwnedBotsBySpace map[string][]string
}

// ContextKind describes the state of the include=context payload for a
// [Principal]. Callers should switch on this value rather than testing Spaces
// for nil, because an empty slice is a legitimate v2+ response.
type ContextKind int

// Context state values. See design doc §2.2.
const (
	// ContextNotRequested means the verifier did not request include=context
	// (e.g. bot / api-key realms where context is server-authoritative already).
	ContextNotRequested ContextKind = iota
	// ContextIncluded means the server returned context_included=true and the
	// Spaces / OwnedBotsBySpace fields are populated (possibly with empty maps).
	ContextIncluded
	// ContextNotIncluded means the server explicitly returned
	// context_included=false. Currently unreachable against server v3
	// (server-side omitempty on context_included erases explicit false on the
	// wire). Preserved for a future server that drops omitempty. Callers
	// SHOULD NOT rely on this state being observed today.
	ContextNotIncluded
	// ContextUnknownServer means the response omitted the context_included
	// field. Ambiguous by design: the server is either pre-v2 (never emits the
	// field) OR v3+ that declined this call (omitempty erased explicit false).
	// Callers MUST fail-closed and MUST NOT infer authorisation from Spaces /
	// OwnedBotsBySpace on the same response.
	ContextUnknownServer
)

// Credential is the extracted raw credential plus its inferred [PrincipalKind].
// Kind is set by [ExtractCredential] via prefix inspection; the raw string is
// what will be passed to a [Verifier.Verify] call.
type Credential struct {
	Kind PrincipalKind
	Raw  string
}

// Verifier verifies a raw credential against octo-server and returns a
// [Principal] on success. Implementations must be safe for concurrent use.
type Verifier interface {
	// Kind returns the realm this verifier handles.
	Kind() PrincipalKind
	// Verify resolves credential into a Principal. On failure it returns a
	// typed [*Error]; callers can use [errors.Is] against the package sentinels.
	Verify(ctx context.Context, credential string) (*Principal, error)
}

// MultiVerifier is a facade Verifier that dispatches to a per-kind child
// verifier based on the credential prefix (see [NewMultiVerifier] for the
// dispatch rules). The zero value is not usable; construct via
// [NewMultiVerifier].
type MultiVerifier interface {
	Verifier
	// Register adds or replaces the child verifier for its Kind and returns
	// the receiver to allow chaining.
	Register(v Verifier) MultiVerifier
}

// NewMultiVerifier builds a [MultiVerifier] populated with the given child
// verifiers. If two verifiers share a Kind, the later one wins.
//
// Dispatch rules (design doc §3):
//   - empty string → [ErrInvalidCredential]
//   - "uk_" + total length >= 35 → api-key realm
//   - "bf_" → bot realm
//   - "app_" → bot realm (reserved; forwarded to the bot child verifier)
//   - otherwise → session realm
//
// A dispatch to a realm with no registered child verifier returns an
// [ErrInvalidCredential]-flavored error naming the missing realm; callers
// typically register all three realms via NewFullMultiVerifier-style helpers
// defined by verifier-implementation packages.
func NewMultiVerifier(verifiers ...Verifier) MultiVerifier {
	m := &multiVerifier{children: make(map[PrincipalKind]Verifier, 3)}
	for _, v := range verifiers {
		if v == nil {
			continue
		}
		m.children[v.Kind()] = v
	}
	return m
}

// multiVerifier is the default MultiVerifier implementation.
type multiVerifier struct {
	children map[PrincipalKind]Verifier
}

// Kind reports the facade kind. It is never a real realm; callers should
// inspect the returned [Principal.Kind] instead.
func (m *multiVerifier) Kind() PrincipalKind {
	return PrincipalKind("multi")
}

func (m *multiVerifier) Register(v Verifier) MultiVerifier {
	if v == nil {
		return m
	}
	m.children[v.Kind()] = v
	return m
}

func (m *multiVerifier) Verify(ctx context.Context, credential string) (*Principal, error) {
	kind, err := classifyCredential(credential)
	if err != nil {
		return nil, err
	}
	child, ok := m.children[kind]
	if !ok {
		return nil, &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  fmt.Sprintf("no verifier registered for kind %q", kind),
			Verifier: kind,
		}
	}
	return child.Verify(ctx, credential)
}

// classifyCredential applies the design-doc §3 dispatch rules. It is used by
// both [MultiVerifier] and [ExtractCredential] so the two stay in lock-step.
func classifyCredential(credential string) (PrincipalKind, error) {
	if credential == "" {
		return "", &Error{
			Kind:    ErrKindInvalidCredential,
			Message: "empty credential",
		}
	}
	switch {
	case strings.HasPrefix(credential, PrefixUK):
		if len(credential) < MinAPIKeyLength {
			return "", &Error{
				Kind:     ErrKindInvalidCredential,
				Message:  "api key too short",
				Verifier: KindAPIKey,
			}
		}
		return KindAPIKey, nil
	case strings.HasPrefix(credential, PrefixBF):
		return KindBot, nil
	case strings.HasPrefix(credential, PrefixApp):
		// Reserved for App Bot tokens; SDK v1 forwards to the bot verifier so
		// downstream implementations can decide whether to accept.
		return KindBot, nil
	default:
		return KindSession, nil
	}
}
