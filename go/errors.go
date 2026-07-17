package octoauth

import (
	"errors"
	"fmt"
)

// ErrorKind classifies an SDK error into one of five stable buckets that
// callers and middleware can switch on without inspecting string messages.
// See design doc §5.1.
type ErrorKind int

// Error kinds. New values must be appended (existing ints are load-bearing
// for the sentinel comparisons below and for stable metrics labels).
const (
	// ErrKindInvalidCredential means the caller-supplied credential was
	// malformed, expired, unknown, or otherwise rejected by octo-server as
	// unauthorized. Middleware maps this to HTTP 401.
	ErrKindInvalidCredential ErrorKind = iota
	// ErrKindDisabled means the credential authenticated but the underlying
	// principal is disabled or the realm is turned off. HTTP 403.
	ErrKindDisabled
	// ErrKindInfraFailure means octo-server or the network in front of it
	// failed in a way that leaves the caller in the dark. HTTP 503.
	ErrKindInfraFailure
	// ErrKindPreV2Server is an internal signal that the server did not return
	// the include=context envelope. Verifiers surface it via
	// [ContextUnknownServer] on the [Principal] rather than aborting.
	ErrKindPreV2Server
	// ErrKindForbidden means the credential authenticated but the caller is
	// not authorized for the requested realm or space. HTTP 403.
	ErrKindForbidden
)

// String returns a stable, snake_case label for the kind. It is suitable as
// a metric or log tag; it is not intended for user-facing responses.
func (k ErrorKind) String() string {
	switch k {
	case ErrKindInvalidCredential:
		return "invalid_credential"
	case ErrKindDisabled:
		return "disabled"
	case ErrKindInfraFailure:
		return "infra_failure"
	case ErrKindPreV2Server:
		return "pre_v2_server"
	case ErrKindForbidden:
		return "forbidden"
	default:
		return fmt.Sprintf("unknown(%d)", int(k))
	}
}

// Error is the typed error returned by every SDK entry point. Callers should
// compare against the package sentinels via [errors.Is] rather than by pointer
// equality, since verifier implementations construct fresh values with
// populated Message / Cause / Verifier fields.
type Error struct {
	// Kind is the coarse-grained bucket. Compare via errors.Is with the
	// package sentinels (ErrInvalidCredential, ErrDisabled, ErrInfraFailure,
	// ErrForbidden).
	Kind ErrorKind
	// Message is a diagnostic string for logs. It is NOT safe to echo to API
	// callers verbatim — the default middleware error mapper substitutes
	// generic responses to avoid leaking enumeration signals.
	Message string
	// Cause is the underlying error (network, decode, etc.), if any.
	Cause error
	// Verifier records which realm produced the error, when known.
	Verifier PrincipalKind
}

// Sentinel errors for use with [errors.Is]. Each sentinel carries only a
// Kind so that any [*Error] with a matching Kind reports true.
//
// ErrPreV2Server is intentionally not exposed as a sentinel — it is handled
// inside verifier implementations by attaching [ContextUnknownServer] to the
// principal, never bubbled up as an error to callers.
var (
	ErrInvalidCredential = &Error{Kind: ErrKindInvalidCredential}
	ErrDisabled          = &Error{Kind: ErrKindDisabled}
	ErrInfraFailure      = &Error{Kind: ErrKindInfraFailure}
	ErrForbidden         = &Error{Kind: ErrKindForbidden}
)

// Error implements the error interface. The format includes the kind, an
// optional verifier tag, the message, and the wrapped cause when present.
func (e *Error) Error() string {
	if e == nil {
		return "<nil octo-auth error>"
	}
	head := e.Kind.String()
	if e.Verifier != "" {
		head = head + "[" + string(e.Verifier) + "]"
	}
	switch {
	case e.Message != "" && e.Cause != nil:
		return fmt.Sprintf("octoauth: %s: %s: %v", head, e.Message, e.Cause)
	case e.Message != "":
		return fmt.Sprintf("octoauth: %s: %s", head, e.Message)
	case e.Cause != nil:
		return fmt.Sprintf("octoauth: %s: %v", head, e.Cause)
	default:
		return "octoauth: " + head
	}
}

// Unwrap returns the underlying [Cause] so that [errors.Is] and [errors.As]
// can walk into transport-layer errors.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Is reports whether target is either the same [*Error] pointer or another
// [*Error] with the same Kind. This lets callers write
// `errors.Is(err, octoauth.ErrInvalidCredential)` regardless of which
// verifier constructed err.
func (e *Error) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	var other *Error
	if !errors.As(target, &other) {
		return false
	}
	return e.Kind == other.Kind
}
