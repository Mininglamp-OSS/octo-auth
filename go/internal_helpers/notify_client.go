// Package internalhelpers provides side-channel helpers for services that
// need to talk to octo-server (and octo-adjacent services) using the
// non-user-realm credential paths — the X-Internal-Token producer channel
// (see [NotifyClient]) and the X-*-Token consumer middleware (see
// [NewInternalTokenGinMiddleware] / [WrapInternalTokenNetHTTP]).
//
// These helpers are deliberately independent of the [Verifier] interface:
// they are service-to-service, not user-to-service, so they never build a
// [octoauth.Principal].
package internalhelpers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// DefaultNotifyTimeout is the fallback HTTP timeout when NotifyConfig.Timeout
// is zero. Ten seconds matches the internal-notify contract's SLA and the
// SMTP-style "fire and reasonably wait" pattern used by smart-summary and
// matter.
const DefaultNotifyTimeout = 10 * time.Second

// NotifyConfig configures a [NotifyClient].
//
// Required fields:
//   - BaseURL:     the target service base URL, e.g. https://octo-server:8090
//   - TokenEnvVar: the process env var name to read the shared-secret from,
//     e.g. "SUMMARY_NOTIFY_TOKEN"
//
// Optional fields fall back to safe defaults (see field docs).
type NotifyConfig struct {
	BaseURL     string
	TokenEnvVar string

	HTTPClient *http.Client  // default &http.Client{Timeout: Timeout}
	Timeout    time.Duration // default DefaultNotifyTimeout
	Logger     *slog.Logger  // default slog.Default()
	// NotifyPath overrides the default /v1/internal/notify endpoint path.
	// Leave empty to use the default; must start with "/" when set.
	NotifyPath string
}

// defaultNotifyPath is the octo-server internal-notify endpoint path.
const defaultNotifyPath = "/v1/internal/notify"

// NotifyClient posts service-authenticated notifications to octo-server via
// the shared-secret X-Internal-Token producer channel. Concurrent use is
// safe.
//
// The zero value is not usable; construct via [NewNotifyClient].
type NotifyClient struct {
	baseURL string
	path    string
	token   string
	client  *http.Client
	logger  *slog.Logger
}

// NewNotifyClient builds a [NotifyClient] from cfg. It reads the token from
// os.Getenv(cfg.TokenEnvVar) at construction time and returns an error when
// the value is empty — a "fail-closed at startup" posture that prevents the
// server from silently degrading into an unauthenticated caller.
//
// Errors:
//   - BaseURL empty
//   - TokenEnvVar empty
//   - env var not set or set to empty
func NewNotifyClient(cfg NotifyConfig) (*NotifyClient, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("octoauth/internal_helpers: NotifyConfig.BaseURL is required")
	}
	if cfg.TokenEnvVar == "" {
		return nil, errors.New("octoauth/internal_helpers: NotifyConfig.TokenEnvVar is required")
	}
	token := os.Getenv(cfg.TokenEnvVar)
	if token == "" {
		return nil, fmt.Errorf("octoauth/internal_helpers: env var %q is empty (fail-closed)", cfg.TokenEnvVar)
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultNotifyTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	path := cfg.NotifyPath
	if path == "" {
		path = defaultNotifyPath
	}
	return &NotifyClient{
		baseURL: cfg.BaseURL,
		path:    path,
		token:   token,
		client:  client,
		logger:  logger,
	}, nil
}

// NotifyRequest is the payload sent to /v1/internal/notify. In v1 the shape
// is intentionally minimal (channel_id + message); callers who need to send
// a different shape can pre-marshal it into [NotifyRequest.RawBody] and
// leave the primary fields empty.
type NotifyRequest struct {
	ChannelID string `json:"channel_id,omitempty"`
	Message   string `json:"message,omitempty"`

	// RawBody, when non-nil, is sent verbatim as the request body and
	// the ChannelID/Message fields are ignored. Useful for callers whose
	// notify contract has already been agreed with the server and does
	// not match the v1 minimal shape.
	RawBody json.RawMessage `json:"-"`
}

// Send posts req to the notify endpoint. It is fire-and-forget in the sense
// that response bodies are drained but not parsed; only the HTTP status is
// consulted. A non-2xx status is returned as an error; the underlying body
// is NOT included so log-scrapers cannot enumerate server-side messages
// leaked via the caller's error path.
func (c *NotifyClient) Send(ctx context.Context, req NotifyRequest) error {
	var body []byte
	if len(req.RawBody) > 0 {
		body = req.RawBody
	} else {
		encoded, err := json.Marshal(req)
		if err != nil {
			return fmt.Errorf("octoauth/internal_helpers: encode notify request: %w", err)
		}
		body = encoded
	}

	url := c.baseURL + c.path
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("octoauth/internal_helpers: build notify request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-Internal-Token", c.token)

	resp, err := c.client.Do(httpReq)
	if err != nil {
		c.logger.Debug("octoauth/internal_helpers: notify transport error",
			slog.String("endpoint", c.path),
			slog.String("token_hint", maskToken(c.token)),
		)
		return fmt.Errorf("octoauth/internal_helpers: notify request failed: %w", err)
	}
	defer resp.Body.Close()
	// Drain the body so the connection can be reused.
	_, _ = io.Copy(io.Discard, resp.Body)

	c.logger.Debug("octoauth/internal_helpers: notify sent",
		slog.String("endpoint", c.path),
		slog.Int("status", resp.StatusCode),
		slog.String("token_hint", maskToken(c.token)),
	)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("octoauth/internal_helpers: notify failed: status %d", resp.StatusCode)
	}
	return nil
}

// maskToken returns a short prefix + "..." suitable for slog. Full-length
// masking is intentional — even 8 characters of an internal shared secret
// should not appear in application logs. Callers who need higher-fidelity
// diagnostics should use their metrics pipeline, not the logger.
func maskToken(t string) string {
	if len(t) < 8 {
		return "***"
	}
	return t[:8] + "..."
}
