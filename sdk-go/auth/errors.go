package auth

import "errors"

// AuthKind tags the kind of token that authenticated the current request.
// Stored on the request context under CtxKeyAuthKind; downstream handlers
// read it via GetAuthKind. The Scope* constants in scope.go gate routes
// to a subset.
type AuthKind string

const (
	AuthKindUnknown AuthKind = ""
	AuthKindSession AuthKind = "session" // user session token (no prefix)
	AuthKindBot     AuthKind = "bot"     // bf_ or app_ prefix
	AuthKindAPIKey  AuthKind = "apikey"  // uk_ prefix
)

// Error code constants mirror octo-auth/contract/errors-v1.yaml. They
// appear as the `code` field of ErrorEnvelope responses and in SDK-side
// errors that don't reach octo-server (e.g. bad prefix).
const (
	CodeTokenMissing        = "AUTH_TOKEN_MISSING"
	CodeTokenInvalid        = "AUTH_TOKEN_INVALID"
	CodeBotUnavailable      = "AUTH_BOT_UNAVAILABLE"
	CodeKindMismatch        = "AUTH_KIND_MISMATCH"
	CodeSpaceForbidden      = "AUTH_SPACE_FORBIDDEN"
	CodeUpstreamUnavailable = "AUTH_UPSTREAM_UNAVAILABLE"
)

// SDK-side sentinel errors. These are returned by Client methods to
// signal what happened so the middleware can map to the right HTTP
// response code (see middleware.go writeError). Downstream code that
// uses Client directly can errors.Is against these.
var (
	// ErrTokenMissing — the Authorization header / token header was
	// absent or unparseable.
	ErrTokenMissing = errors.New("octoauth: token missing or malformed")
	// ErrTokenInvalid — octo-server returned 401, or SDK prefix validation
	// rejected the token client-side.
	ErrTokenInvalid = errors.New("octoauth: token invalid or expired")
	// ErrBotUnavailable — octo-server returned 503 AUTH_BOT_UNAVAILABLE
	// (App Bot exists but is unpublished).
	ErrBotUnavailable = errors.New("octoauth: bot is currently unavailable")
	// ErrKindMismatch — the route's required Scope doesn't allow the
	// token kind on the request. Always a downstream routing bug
	// (handlers should not see this in normal flow).
	ErrKindMismatch = errors.New("octoauth: token kind not allowed on this endpoint")
	// ErrSpaceForbidden — X-Space-Id is set to a space the verified
	// identity is not a member of (fail-closed when context_included).
	ErrSpaceForbidden = errors.New("octoauth: X-Space-Id not in verified spaces")
	// ErrUpstreamUnavailable — octo-server returned 5xx or timed out.
	// SDK middleware maps this to 503 so callers retry rather than
	// dropping the token.
	ErrUpstreamUnavailable = errors.New("octoauth: upstream verification unavailable")
)
