package octoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// verifyResultTag classifies a Verify outcome for [MetricsCollector]
// telemetry. It is used exclusively by the concrete verifier implementations.
const (
	verifyResultHit    = "hit"
	verifyResultMissOK = "miss-ok"
	// verifyResultAuthErr is a caller-visible auth reject (401 / 403 mapped to
	// InvalidCredential / Disabled). It is distinct from an infra failure so
	// dashboards can tell "we rejected the user" apart from "we couldn't
	// reach octo-server".
	verifyResultAuthErr = "miss-err"
	verifyResultInfra   = "error"
)

// maxLoggedBodyBytes is the ceiling for slog.Debug body echoes. Keeping this
// small keeps log volume bounded while still surfacing octo-server's own
// diagnostics for local debugging.
const maxLoggedBodyBytes = 200

// doVerifyRequest builds and executes a JSON-body POST against
// cfg.BaseURL+endpoint (endpoint may include a query string, e.g.
// "/v1/auth/verify?include=context"). On success it returns the raw response
// body bytes for the caller to decode. On failure it returns a typed [*Error]
// whose Kind reflects the surveyed status → error mapping.
//
// Status mapping:
//
//	2xx → nil error, body returned
//	401 → ErrKindInvalidCredential
//	403 → ErrKindDisabled
//	other 4xx/5xx → ErrKindInfraFailure
//	transport / decode errors → ErrKindInfraFailure
//
// Server-side response bodies are never surfaced in Error.Message (that would
// leak enumeration signals through the reverse proxy). They are logged to
// cfg.Logger at Debug level with a 200-byte cap.
func doVerifyRequest(
	ctx context.Context,
	cfg *Config,
	endpoint string,
	reqBody any,
	verifier PrincipalKind,
) ([]byte, error) {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, &Error{
			Kind:     ErrKindInfraFailure,
			Message:  "encode verify request body",
			Cause:    err,
			Verifier: verifier,
		}
	}

	url := cfg.BaseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, &Error{
			Kind:     ErrKindInfraFailure,
			Message:  "build verify request",
			Cause:    err,
			Verifier: verifier,
		}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		// Include context.Canceled / DeadlineExceeded / net errors under
		// InfraFailure — callers can errors.Is against context sentinels
		// through the Unwrap chain if they need to distinguish.
		return nil, &Error{
			Kind:     ErrKindInfraFailure,
			Message:  "verify request failed",
			Cause:    err,
			Verifier: verifier,
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &Error{
			Kind:     ErrKindInfraFailure,
			Message:  "read verify response body",
			Cause:    err,
			Verifier: verifier,
		}
	}

	if authErr := statusToError(resp.StatusCode, verifier); authErr != nil {
		logVerifyResult(cfg, verifier, endpoint, resp.StatusCode, body)
		return nil, authErr
	}
	return body, nil
}

// statusToError converts an HTTP status code to a typed [*Error] or nil for
// 2xx. It is factored out so tests can table-drive the mapping without
// spinning up a mock server.
func statusToError(status int, verifier PrincipalKind) *Error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == http.StatusUnauthorized:
		return &Error{
			Kind:     ErrKindInvalidCredential,
			Message:  "server rejected credential",
			Verifier: verifier,
		}
	case status == http.StatusForbidden:
		return &Error{
			Kind:     ErrKindDisabled,
			Message:  "credential disabled",
			Verifier: verifier,
		}
	default:
		return &Error{
			Kind:     ErrKindInfraFailure,
			Message:  fmt.Sprintf("unexpected status %d", status),
			Verifier: verifier,
		}
	}
}

// logVerifyResult emits a Debug-level log capturing the octo-server response
// summary. It is a no-op when the logger is disabled at Debug level.
func logVerifyResult(cfg *Config, verifier PrincipalKind, endpoint string, status int, body []byte) {
	if cfg == nil || cfg.Logger == nil {
		return
	}
	snippet := body
	if len(snippet) > maxLoggedBodyBytes {
		snippet = snippet[:maxLoggedBodyBytes]
	}
	cfg.Logger.LogAttrs(context.Background(), slog.LevelDebug,
		"octoauth: verify response",
		slog.String("verifier", string(verifier)),
		slog.String("endpoint", endpoint),
		slog.Int("status", status),
		slog.String("body_snippet", string(snippet)),
	)
}

// decodeVerifyResponse is a small wrapper that maps JSON decode errors to a
// consistent [*Error] shape. Verifier implementations call this immediately
// after doVerifyRequest.
func decodeVerifyResponse(body []byte, dst any, verifier PrincipalKind) error {
	if err := json.Unmarshal(body, dst); err != nil {
		return &Error{
			Kind:     ErrKindInfraFailure,
			Message:  "decode verify response",
			Cause:    err,
			Verifier: verifier,
		}
	}
	return nil
}

// verifyContext bundles the moving parts a verifier needs on every Verify
// call: cache keys, elapsed timer, and the shared config. It is a private
// helper to keep the per-verifier files small.
type verifyContext struct {
	cfg      *Config
	verifier PrincipalKind
	posKey   string
	negKey   string
	start    time.Time
	ttl      time.Duration
}

// newVerifyContext builds a verifyContext for the given verifier / credential.
// keyPrefix is one of "s:" / "b:" / "k:" per design doc §6.
//
// The resolved [Config.RequestIncludeContext] flag is folded into the cache
// key as a "c:" (include=context) or "n:" (no context) segment. This
// prevents two verifier instances that share a Cache but disagree on
// RequestIncludeContext from cross-serving each other's Principals — a
// no-context Principal has [ContextNotRequested], which the enrich helper
// treats as a no-op, so serving it to a caller expecting [ContextIncluded]
// would silently skip X-Space-Id membership validation. The bot verifier
// ignores RequestIncludeContext but still gets the segment for a uniform
// key layout. Reviewer P1-C.
func newVerifyContext(cfg *Config, verifier PrincipalKind, keyPrefix, credential string, ttl time.Duration) verifyContext {
	base := credential
	if cfg.HashCacheKey != nil && *cfg.HashCacheKey {
		base = HashCacheKey(credential)
	}
	ctxTag := "n:"
	if cfg.RequestIncludeContext != nil && *cfg.RequestIncludeContext {
		ctxTag = "c:"
	}
	pos := keyPrefix + ctxTag + base
	return verifyContext{
		cfg:      cfg,
		verifier: verifier,
		posKey:   pos,
		negKey:   pos + ":neg",
		start:    time.Now(),
		ttl:      ttl,
	}
}

// lookupCache returns (principal, err, hit). A hit is either a positive
// (principal != nil, err == nil) or negative (principal == nil, err != nil)
// cached result. On miss, all three zero values are returned.
//
// A stored value whose runtime type does not match the expected shape
// (*Principal for positive, *Error for negative) is logged at warn level
// once and treated as a miss so callers fall through to a live verify.
func (vc verifyContext) lookupCache(ctx context.Context) (*Principal, error, bool) {
	if val, ok := vc.cfg.Cache.Get(ctx, vc.posKey); ok {
		if p, ok := val.(*Principal); ok {
			return p, nil, true
		}
		vc.cfg.Logger.Warn("octoauth: cache returned wrong type for positive key",
			slog.String("verifier", string(vc.verifier)),
			slog.String("expected", "*octoauth.Principal"),
			slog.String("got", fmt.Sprintf("%T", val)),
		)
	}
	if val, ok := vc.cfg.Cache.Get(ctx, vc.negKey); ok {
		if e, ok := val.(*Error); ok {
			return nil, e, true
		}
		vc.cfg.Logger.Warn("octoauth: cache returned wrong type for negative key",
			slog.String("verifier", string(vc.verifier)),
			slog.String("expected", "*octoauth.Error"),
			slog.String("got", fmt.Sprintf("%T", val)),
		)
	}
	return nil, nil, false
}

// finalize records metrics and caches the outcome. Callers pass the resolved
// principal + error and finalize decides which side of the split to cache.
//
// Rules:
//   - positive principal → cache under posKey with ttl (SessionTTL / BotTTL / APIKeyTTL)
//   - InvalidCredential / Disabled → cache under negKey with cfg.NegativeTTL
//   - InfraFailure → NOT cached (so a resolving upstream is not blocked
//     behind a stale reject)
func (vc verifyContext) finalize(ctx context.Context, p *Principal, err error) (*Principal, error) {
	elapsed := time.Since(vc.start)
	if err != nil {
		var authErr *Error
		if errors.As(err, &authErr) {
			vc.cfg.Metrics.IncErrorByKind(vc.verifier, authErr.Kind)
			switch authErr.Kind {
			case ErrKindInvalidCredential, ErrKindDisabled:
				vc.cfg.Cache.Set(ctx, vc.negKey, authErr, vc.cfg.NegativeTTL)
				vc.cfg.Metrics.ObserveVerifyDuration(vc.verifier, verifyResultAuthErr, elapsed)
				return nil, err
			default:
				vc.cfg.Metrics.ObserveVerifyDuration(vc.verifier, verifyResultInfra, elapsed)
				return nil, err
			}
		}
		vc.cfg.Metrics.ObserveVerifyDuration(vc.verifier, verifyResultInfra, elapsed)
		return nil, err
	}
	vc.cfg.Cache.Set(ctx, vc.posKey, p, vc.ttl)
	vc.cfg.Metrics.ObserveVerifyDuration(vc.verifier, verifyResultMissOK, elapsed)
	return p.Clone(), nil
}

// recordCacheHit records a cache-hit outcome. The Principal (when non-nil) is
// deep-cloned so callers can mutate the returned value without racing with
// concurrent verifies that share the cached instance.
func (vc verifyContext) recordCacheHit(p *Principal, err error) (*Principal, error) {
	vc.cfg.Metrics.IncCacheHit(vc.verifier, true)
	vc.cfg.Metrics.ObserveVerifyDuration(vc.verifier, verifyResultHit, time.Since(vc.start))
	return p.Clone(), err
}

// recordCacheMiss records that a lookup missed and the verifier is about to
// call out to octo-server.
func (vc verifyContext) recordCacheMiss() {
	vc.cfg.Metrics.IncCacheHit(vc.verifier, false)
}
