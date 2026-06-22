// Package contract contains the typed DTOs for octo-auth/contract/auth-v1.yaml.
// Hand-curated for v1 — small, stable, no generator dependency. Future
// contract revisions may switch to an openapi-codegen pipeline.
//
// These types are the SDK-side mirror of octo-server's
// modules/auth/contract.go; field names and JSON tags MUST match exactly
// or downstream services will silently miss fields. The
// .github/workflows/contract.yml CI cross-checks both sides on every
// change.
package contract

// VerifyUserReq is the request body for POST /v1/auth/verify.
type VerifyUserReq struct {
	Token   string   `json:"token"`
	Include []string `json:"include,omitempty"`
}

// VerifyUserResp is the response body for POST /v1/auth/verify.
type VerifyUserResp struct {
	SchemaVersion    int                 `json:"schema_version"`
	Kind             string              `json:"kind"`
	UID              string              `json:"uid"`
	Name             string              `json:"name"`
	Role             string              `json:"role"`
	Language         string              `json:"language,omitempty"`
	OwnedBots        []OwnedBot          `json:"owned_bots"`
	ContextIncluded  bool                `json:"context_included,omitempty"`
	Spaces           []string            `json:"spaces,omitempty"`
	OwnedBotsBySpace map[string][]string `json:"owned_bots_by_space,omitempty"`
}

// OwnedBot is the per-bot summary embedded in VerifyUserResp.OwnedBots.
type OwnedBot struct {
	UID  string `json:"uid"`
	Name string `json:"name"`
}

// VerifyBotReq is the request body for POST /v1/auth/verify-bot.
type VerifyBotReq struct {
	BotToken string `json:"bot_token"`
}

// VerifyBotResp is the response body for POST /v1/auth/verify-bot.
type VerifyBotResp struct {
	SchemaVersion int    `json:"schema_version"`
	Kind          string `json:"kind"`
	BotUID        string `json:"bot_uid"`
	BotName       string `json:"bot_name"`
	BotKind       string `json:"bot_kind"`
	OwnerUID      string `json:"owner_uid"`
	OwnerName     string `json:"owner_name"`
	Scope         string `json:"scope,omitempty"`
	SpaceID       string `json:"space_id"`
	Language      string `json:"language,omitempty"`
}

// VerifyAPIKeyReq is the request body for POST /v1/auth/verify-api-key.
type VerifyAPIKeyReq struct {
	APIKey  string   `json:"api_key"`
	Include []string `json:"include,omitempty"`
}

// VerifyAPIKeyResp is the response body for POST /v1/auth/verify-api-key.
type VerifyAPIKeyResp struct {
	SchemaVersion    int                 `json:"schema_version"`
	Kind             string              `json:"kind"`
	UID              string              `json:"uid"`
	KeyID            string              `json:"key_id"`
	ContextIncluded  bool                `json:"context_included,omitempty"`
	SpaceID          string              `json:"space_id,omitempty"`
	OwnedBotsBySpace map[string][]string `json:"owned_bots_by_space,omitempty"`
}

// ErrorEnvelope is the canonical error wire shape returned by octo-server's
// httperr.ResponseErrorL. The status field is the *intended* HTTP status —
// octo-server may pin the actual response status to 400 for legacy
// compatibility (see CLAUDE.md in octo-server).
type ErrorEnvelope struct {
	SchemaVersion int   `json:"schema_version"`
	Error         Error `json:"error"`
}

// Error is the inner shape of ErrorEnvelope.Error.
type Error struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
}
