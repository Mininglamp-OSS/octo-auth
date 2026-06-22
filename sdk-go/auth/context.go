package auth

import "github.com/gin-gonic/gin"

// Context keys under which the SDK middleware stores verified identity.
// Downstream code should read these via the GetXxx accessors below, not
// by key name, so a future key rename doesn't break callers.
const (
	CtxKeyLoginUID           = "octoauth.login_uid"
	CtxKeyName               = "octoauth.name"
	CtxKeyRole               = "octoauth.role"
	CtxKeyLanguage           = "octoauth.language"
	CtxKeyAuthKind           = "octoauth.auth_kind"
	CtxKeySpaceID            = "octoauth.space_id"
	CtxKeyRelatedUIDs        = "octoauth.related_uids"
	CtxKeyVerifiedSpaces     = "octoauth.verified_spaces"
	CtxKeyOwnedBotsBySpace   = "octoauth.owned_bots_by_space"
	CtxKeyContextIncluded    = "octoauth.context_included"
	CtxKeyBotKind            = "octoauth.bot_kind"
	CtxKeyOwnerUID           = "octoauth.owner_uid"
	CtxKeyOwnerName          = "octoauth.owner_name"
	CtxKeyAppBotScope        = "octoauth.app_bot_scope"
)

// GetLoginUID returns the authenticated principal's UID (user / bot UID
// for sessions and bots; API-key owner UID for daemon calls). Empty
// string if the middleware did not run or rejected the request.
func GetLoginUID(c *gin.Context) string { return getString(c, CtxKeyLoginUID) }

// GetName returns the display name (user name / bot name); empty for
// API-key callers (the key resolves to an owner UID, not a name).
func GetName(c *gin.Context) string { return getString(c, CtxKeyName) }

// GetRole returns the system role for user sessions ("" / "admin" /
// "superAdmin"); empty for bots and API keys.
func GetRole(c *gin.Context) string { return getString(c, CtxKeyRole) }

// GetLanguage returns the BCP-47 language tag the verify response
// carried (user.language for sessions, bot owner's language for bots).
// Empty when the response omitted the field — caller should fall back
// to Accept-Language or its own default.
func GetLanguage(c *gin.Context) string { return getString(c, CtxKeyLanguage) }

// GetOwnerName returns the bot owner's display name for AuthKindBot
// requests; empty otherwise (and empty for bots where the verify
// response omitted owner_name, e.g. unhydrated App Bot registry hits).
func GetOwnerName(c *gin.Context) string { return getString(c, CtxKeyOwnerName) }

// GetAuthKind tells what kind of token authenticated the request.
func GetAuthKind(c *gin.Context) AuthKind {
	if v, ok := c.Get(CtxKeyAuthKind); ok {
		if s, ok := v.(AuthKind); ok {
			return s
		}
	}
	return AuthKindUnknown
}

// GetSpaceID returns the X-Space-Id the request came in with (or the
// bot's binding space for App Bots / API Keys with a space binding).
func GetSpaceID(c *gin.Context) string { return getString(c, CtxKeySpaceID) }

// GetRelatedUIDs returns the set of UIDs whose data this principal is
// allowed to see — typically [self, owned_bots...] for a user session,
// [self, owner] for a bot. Empty for API keys (caller composes its own).
func GetRelatedUIDs(c *gin.Context) []string {
	if v, ok := c.Get(CtxKeyRelatedUIDs); ok {
		if s, ok := v.([]string); ok {
			return s
		}
	}
	return nil
}

// GetVerifiedSpaces returns the list of spaces the verify response
// authoritatively confirmed the principal is a member of. Populated
// only when the request asked for include=context. RequireSpaceMember
// reads this to fail-closed when X-Space-Id is not in the list.
func GetVerifiedSpaces(c *gin.Context) []string {
	if v, ok := c.Get(CtxKeyVerifiedSpaces); ok {
		if s, ok := v.([]string); ok {
			return s
		}
	}
	return nil
}

// GetOwnedBotsBySpace returns the per-space bot ownership map populated
// when include=context was set on the verify request. Empty map vs nil
// is meaningful: empty = verified-but-none, nil = not-asked.
func GetOwnedBotsBySpace(c *gin.Context) map[string][]string {
	if v, ok := c.Get(CtxKeyOwnedBotsBySpace); ok {
		if s, ok := v.(map[string][]string); ok {
			return s
		}
	}
	return nil
}

// IsContextIncluded reports whether the verify response carried the
// authoritative spaces[] / owned_bots_by_space{} context. Used by
// RequireSpaceMember to decide between fail-closed (true) and
// log-warn-and-pass (false, for compatibility with pre-context-aware
// octo-server versions).
func IsContextIncluded(c *gin.Context) bool {
	if v, ok := c.Get(CtxKeyContextIncluded); ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

// GetBotKind returns "user" or "app" for AuthKindBot requests; empty
// otherwise.
func GetBotKind(c *gin.Context) string { return getString(c, CtxKeyBotKind) }

// GetOwnerUID returns the bot owner UID for AuthKindBot requests; empty
// otherwise.
func GetOwnerUID(c *gin.Context) string { return getString(c, CtxKeyOwnerUID) }

// GetAppBotScope returns "platform" or "space" for AuthKindBot
// requests with BotKind=="app"; empty otherwise.
func GetAppBotScope(c *gin.Context) string { return getString(c, CtxKeyAppBotScope) }

func getString(c *gin.Context, k string) string {
	if v, ok := c.Get(k); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
