package auth

// Scope selects which token kinds the middleware accepts on a route.
// Mounting middleware with a specific Scope is how a service expresses
// "this endpoint is only for daemons" / "only for browser sessions" /
// etc. Mismatches produce 403 AUTH_KIND_MISMATCH.
type Scope int

const (
	// ScopeAny accepts every token kind. Use sparingly — most routes
	// have a natural kind they expect.
	ScopeAny Scope = iota
	// ScopeWeb accepts user session tokens only.
	ScopeWeb
	// ScopeBot accepts bot tokens (bf_ or app_) only.
	ScopeBot
	// ScopeDaemon accepts API keys (uk_) only.
	ScopeDaemon
)

// allows reports whether the Scope accepts the given AuthKind.
func (s Scope) allows(kind AuthKind) bool {
	switch s {
	case ScopeAny:
		return kind != AuthKindUnknown
	case ScopeWeb:
		return kind == AuthKindSession
	case ScopeBot:
		return kind == AuthKindBot
	case ScopeDaemon:
		return kind == AuthKindAPIKey
	default:
		return false
	}
}

// String returns the human-readable scope name. Used in error log lines.
func (s Scope) String() string {
	switch s {
	case ScopeAny:
		return "any"
	case ScopeWeb:
		return "web"
	case ScopeBot:
		return "bot"
	case ScopeDaemon:
		return "daemon"
	default:
		return "unknown"
	}
}
