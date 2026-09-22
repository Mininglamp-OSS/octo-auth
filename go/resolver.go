package octoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const resolveEndpoint = "/v1/auth/resolve"
const resolveServiceHeader = "X-Octo-Service-Token"

// BotResolveMode selects Bot-self identity or owner delegation.
type BotResolveMode string

const (
	ModeAsBot BotResolveMode = "AS_BOT"
	ModeOBO   BotResolveMode = "OBO"
)

type ResolveResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type ResolveRequest struct {
	Mode     BotResolveMode   `json:"mode"`
	SpaceID  string           `json:"space_id"`
	Action   string           `json:"action,omitempty"`
	Resource *ResolveResource `json:"resource,omitempty"`
}

type ResolvedIdentity struct {
	UID     string `json:"uid"`
	Kind    string `json:"kind"`
	SpaceID string `json:"space_id"`
}

type ResolvedDelegation struct {
	GrantID       int64  `json:"grant_id"`
	MatchedScope  string `json:"matched_scope"`
	PolicyVersion int64  `json:"policy_version"`
	Action        string `json:"action"`
	DecisionID    string `json:"decision_id"`
}

type ResolvedPrincipal struct {
	Mode       BotResolveMode      `json:"mode"`
	Actor      ResolvedIdentity    `json:"actor"`
	Subject    ResolvedIdentity    `json:"subject"`
	Delegation *ResolvedDelegation `json:"delegation,omitempty"`
}

type Resolver interface {
	Resolve(ctx context.Context, credential string, req ResolveRequest) (*ResolvedPrincipal, error)
}

type botResolver struct{ cfg *Config }

// NewResolver constructs the new Bot resolver. A separate per-service token is
// mandatory; a Bot Token cannot authenticate the calling service.
func NewResolver(cfg *Config) Resolver {
	applyDefaults(cfg)
	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.ServiceToken) == "" {
		panic("octoauth: Resolver requires BaseURL and ServiceToken")
	}
	return &botResolver{cfg: cfg}
}

func invalidResolveRequest(message string) error {
	return &Error{Kind: ErrKindInvalidRequest, Message: message, Verifier: KindBot}
}

func resolveProtocolFailure(message string, cause error) error {
	return &Error{Kind: ErrKindInfraFailure, Message: message, Cause: cause, Verifier: KindBot}
}

func (r *botResolver) Resolve(ctx context.Context, credential string, request ResolveRequest) (*ResolvedPrincipal, error) {
	if credential == "" || strings.HasPrefix(credential, PrefixApp) {
		return nil, &Error{Kind: ErrKindInvalidCredential, Message: "unsupported or empty Bot credential", Verifier: KindBot}
	}
	if strings.TrimSpace(request.SpaceID) == "" {
		return nil, invalidResolveRequest("space_id is required")
	}
	switch request.Mode {
	case ModeAsBot:
		if request.Action != "" || request.Resource != nil {
			return nil, invalidResolveRequest("AS_BOT cannot carry Action or resource")
		}
	case ModeOBO:
		if strings.TrimSpace(request.Action) == "" {
			return nil, invalidResolveRequest("OBO requires Action")
		}
	default:
		return nil, invalidResolveRequest("invalid Bot resolve mode")
	}

	input := struct {
		BotToken string `json:"bot_token"`
		ResolveRequest
	}{BotToken: credential, ResolveRequest: request}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, resolveProtocolFailure("encode Resolve request", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.BaseURL+resolveEndpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, resolveProtocolFailure("build Resolve request", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set(resolveServiceHeader, r.cfg.ServiceToken)
	httpReq.Header.Set("Cache-Control", "no-store")
	resp, err := r.cfg.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, resolveProtocolFailure("Resolve request failed", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVerifyBodyBytes+1))
	if err != nil || len(body) > maxVerifyBodyBytes {
		return nil, resolveProtocolFailure("read bounded Resolve response", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resolveWireError(resp.StatusCode, body)
	}
	var out ResolvedPrincipal
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, resolveProtocolFailure("decode Resolve response", err)
	}
	if out.Mode != request.Mode || out.Actor.UID == "" || out.Actor.Kind != "BOT" ||
		out.Actor.SpaceID != request.SpaceID || out.Subject.UID == "" || out.Subject.SpaceID != request.SpaceID {
		return nil, resolveProtocolFailure("Resolve response identity mismatch", nil)
	}
	if request.Mode == ModeAsBot {
		if out.Subject.Kind != "BOT" || out.Subject.UID != out.Actor.UID || out.Delegation != nil {
			return nil, resolveProtocolFailure("AS_BOT response mismatch", nil)
		}
	} else if out.Subject.Kind != "HUMAN" || out.Delegation == nil || out.Delegation.GrantID <= 0 ||
		out.Delegation.Action != request.Action || out.Delegation.MatchedScope != "ALL" {
		return nil, resolveProtocolFailure("OBO response mismatch", nil)
	}
	return &out, nil
}

func resolveWireError(status int, body []byte) error {
	var wire struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return resolveProtocolFailure("invalid Resolve error envelope", err)
	}
	kind := ErrKindInfraFailure
	valid := false
	switch wire.Code {
	case "invalid_mode", "invalid_request", "invalid_obo_request", "missing_space_id":
		kind, valid = ErrKindInvalidRequest, status == http.StatusBadRequest
	case "invalid_credential":
		kind, valid = ErrKindInvalidCredential, status == http.StatusUnauthorized
	case "untrusted_service":
		kind, valid = ErrKindInfraFailure, status == http.StatusUnauthorized
	case "disabled":
		kind, valid = ErrKindDisabled, status == http.StatusForbidden
	case "space_not_allowed", "delegation_denied", "action_not_allowed":
		kind, valid = ErrKindForbidden, status == http.StatusForbidden
	case "infra_failure":
		kind, valid = ErrKindInfraFailure, status == http.StatusServiceUnavailable
	}
	if !valid {
		return resolveProtocolFailure(fmt.Sprintf("unexpected Resolve status/code: %d/%s", status, wire.Code), nil)
	}
	return &Error{Kind: kind, Code: wire.Code, RequestID: wire.RequestID, Message: "Resolve rejected", Verifier: KindBot}
}
