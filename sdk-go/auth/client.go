package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Mininglamp-OSS/octo-auth/sdk-go/contract"
	"github.com/Mininglamp-OSS/octo-auth/sdk-go/metrics"
)

// Options configures a Client. ServerURL is the only required field;
// every other field has a sensible default.
type Options struct {
	// ServerURL is the octo-server base URL (e.g. https://octo-server.example.com).
	// Trailing slash is trimmed; verify paths are appended internally.
	ServerURL string

	// HTTPTimeout bounds one verify call. Default 5s.
	HTTPTimeout time.Duration

	// MaxRetries on idempotent 5xx responses. Default 2. Retries use a
	// fixed 100ms backoff because verify is fast and our caller already
	// holds a request context; longer waits would just thrash.
	MaxRetries int

	// CacheTTL bounds the cache freshness. Default 60s — matches the TTL
	// matter and fleet were using pre-SDK; that 60s is also the maximum
	// token-revocation window from the caller's point of view.
	CacheTTL time.Duration

	// CacheSize is the LRU capacity. Default 10000 entries. Trade-off:
	// larger = better hit rate at high cardinality, more memory.
	CacheSize int

	// HTTPClient lets the caller inject a transport (e.g. with auth
	// headers, custom dialers, or a test round-tripper). Default
	// http.Client{Timeout: HTTPTimeout}.
	HTTPClient *http.Client

	// Logger is the slog.Logger the SDK reports to. Default slog.Default().
	Logger *slog.Logger

	// Collector is the metrics sink. Default
	// metrics.NewPrometheusCollector(prometheus.DefaultRegisterer);
	// pass metrics.NewNoopCollector() for tests / no-prom services.
	Collector metrics.Collector
}

// Client is the SDK's verify client. Construct once per service via New,
// reuse across goroutines (it is safe for concurrent use).
type Client struct {
	opts   Options
	cache  *verifyCache
	log    *slog.Logger
	col    metrics.Collector
	server string
	http   *http.Client
}

// New constructs a Client and applies defaults. Returns an error if
// ServerURL is empty or the cache can't be created.
func New(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.ServerURL) == "" {
		return nil, errors.New("octoauth: Options.ServerURL is required")
	}
	if opts.HTTPTimeout == 0 {
		opts.HTTPTimeout = 5 * time.Second
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 2
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = 60 * time.Second
	}
	if opts.CacheSize == 0 {
		opts.CacheSize = 10000
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: opts.HTTPTimeout}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Collector == nil {
		opts.Collector = metrics.NewNoopCollector()
	}

	cache, err := newVerifyCache(opts.CacheSize, opts.CacheTTL, collectorHook{opts.Collector})
	if err != nil {
		return nil, fmt.Errorf("octoauth: build cache: %w", err)
	}

	return &Client{
		opts:   opts,
		cache:  cache,
		log:    opts.Logger,
		col:    opts.Collector,
		server: strings.TrimRight(opts.ServerURL, "/"),
		http:   opts.HTTPClient,
	}, nil
}

// collectorHook adapts metrics.Collector to verifyCache's smaller hook.
type collectorHook struct{ c metrics.Collector }

func (h collectorHook) ObserveCacheHit(kind string)     { h.c.ObserveCacheHit(kind) }
func (h collectorHook) ObserveCacheEvict(reason string) { h.c.ObserveCacheEvict(reason) }

// VerifyUser verifies a user session token.
//
// Returns a deep copy of the response (Jerry-Xin round-6 P0):
// the cache stores the canonical entry; callers receive a fresh
// clone so any in-place mutation of OwnedBots/Spaces/OwnedBotsBySpace
// can't corrupt later cache hits or race with concurrent middleware
// reads.
func (c *Client) VerifyUser(ctx context.Context, token string, includeContext bool) (*contract.VerifyUserResp, error) {
	const kind = "user"
	if entry, ok := c.cache.Get(kind, token, includeContext); ok {
		c.col.ObserveVerify(kind, "cache_hit", 0)
		if entry.ResultErr != nil {
			return nil, entry.ResultErr
		}
		return cloneUserResp(entry.UserResp.(*contract.VerifyUserResp)), nil
	}

	req := contract.VerifyUserReq{Token: token}
	if includeContext {
		req.Include = []string{"context"}
	}
	start := time.Now()
	var resp contract.VerifyUserResp
	err := c.callVerify(ctx, "/v1/auth/verify", req, &resp)
	c.col.ObserveVerify(kind, resultLabel(err), time.Since(start).Seconds())
	if err != nil {
		// Negative cache only for ErrTokenInvalid. ErrUpstreamUnavailable
		// must NOT be cached — that would make a transient outage stick.
		if errors.Is(err, ErrTokenInvalid) {
			c.cache.Set(kind, token, includeContext, &cachedIdentity{ResultErr: err})
		}
		return nil, err
	}
	c.cache.Set(kind, token, includeContext, &cachedIdentity{UserResp: &resp})
	return cloneUserResp(&resp), nil
}

// VerifyBot verifies a bot token (bf_ for User Bot, app_ for App Bot).
// Bot verify does not take an includeContext flag — the bot response
// shape is fixed at the contract level — so cache uses includeContext=false
// consistently for the bot kind.
//
// Jerry-Xin round-6 P0: the contract (auth-v1.yaml verify-bot
// endpoint) says bot tokens MUST be bf_/app_ prefixed and unprefixed
// tokens are rejected at the SDK layer. Earlier rounds enforced this
// only in the Gin middleware (via kindFromPrefix); a service calling
// Client.VerifyBot directly bypassed the security boundary. Validate
// here too so the contract claim is upheld for every entry point.
func (c *Client) VerifyBot(ctx context.Context, botToken string) (*contract.VerifyBotResp, error) {
	const kind = "bot"
	if !strings.HasPrefix(botToken, prefixBotFather) && !strings.HasPrefix(botToken, prefixAppBot) {
		return nil, ErrTokenInvalid
	}
	if len(botToken) < minBotTokenLen {
		return nil, ErrTokenInvalid
	}
	if entry, ok := c.cache.Get(kind, botToken, false); ok {
		c.col.ObserveVerify(kind, "cache_hit", 0)
		if entry.ResultErr != nil {
			return nil, entry.ResultErr
		}
		return cloneBotResp(entry.BotResp.(*contract.VerifyBotResp)), nil
	}

	start := time.Now()
	var resp contract.VerifyBotResp
	err := c.callVerify(ctx, "/v1/auth/verify-bot", contract.VerifyBotReq{BotToken: botToken}, &resp)
	c.col.ObserveVerify(kind, resultLabel(err), time.Since(start).Seconds())
	if err != nil {
		// Negative-cache ErrTokenInvalid (token never existed). NOT
		// ErrBotUnavailable: that's a transient availability state
		// (bot owner can publish to fix it) and yujiawei P2 review on
		// octo-auth#2 flagged caching it as keeping callers stuck at
		// 503 for the full TTL after a re-publish.
		if errors.Is(err, ErrTokenInvalid) {
			c.cache.Set(kind, botToken, false, &cachedIdentity{ResultErr: err})
		}
		return nil, err
	}
	c.cache.Set(kind, botToken, false, &cachedIdentity{BotResp: &resp})
	return cloneBotResp(&resp), nil
}

// VerifyAPIKey verifies a uk_ API key.
//
// Jerry-Xin round-6 P0: enforce the contract's uk_ prefix at the
// Client method too — see VerifyBot's commentary for the rationale.
func (c *Client) VerifyAPIKey(ctx context.Context, apiKey string, includeContext bool) (*contract.VerifyAPIKeyResp, error) {
	const kind = "apikey"
	if !strings.HasPrefix(apiKey, prefixAPIKey) {
		return nil, ErrTokenInvalid
	}
	if len(apiKey) < minAPIKeyLen {
		return nil, ErrTokenInvalid
	}
	if entry, ok := c.cache.Get(kind, apiKey, includeContext); ok {
		c.col.ObserveVerify(kind, "cache_hit", 0)
		if entry.ResultErr != nil {
			return nil, entry.ResultErr
		}
		return cloneAPIKeyResp(entry.APIKeyResp.(*contract.VerifyAPIKeyResp)), nil
	}

	req := contract.VerifyAPIKeyReq{APIKey: apiKey}
	if includeContext {
		req.Include = []string{"context"}
	}
	start := time.Now()
	var resp contract.VerifyAPIKeyResp
	err := c.callVerify(ctx, "/v1/auth/verify-api-key", req, &resp)
	c.col.ObserveVerify(kind, resultLabel(err), time.Since(start).Seconds())
	if err != nil {
		if errors.Is(err, ErrTokenInvalid) {
			c.cache.Set(kind, apiKey, includeContext, &cachedIdentity{ResultErr: err})
		}
		return nil, err
	}
	c.cache.Set(kind, apiKey, includeContext, &cachedIdentity{APIKeyResp: &resp})
	return cloneAPIKeyResp(&resp), nil
}

// maxVerifyRespBytes caps the auth-path response body read so a
// misbehaving or compromised verify endpoint cannot drive unbounded
// allocation. yujiawei round-6 P2: a multi-MB response on the auth
// hot path could exhaust the process. Verify envelopes are small;
// 1 MiB is generous.
const maxVerifyRespBytes = 1 << 20

// callVerify does the HTTP round-trip + retry on idempotent 5xx +
// response decode. Maps octo-server status codes to sentinel errors.
func (c *Client) callVerify(ctx context.Context, path string, reqBody, respBody any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("octoauth: marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.server+path, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("octoauth: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.http.Do(req)
		if err != nil {
			// yujiawei round-6 P2: branch on caller ctx cancel/deadline
			// so client disconnects don't spike the upstream-timeout
			// metric and trigger false octo-server alerts. Caller-
			// canceled errors short-circuit the retry loop (no point
			// retrying a request the caller has abandoned).
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return ctx.Err()
			}
			c.col.ObserveUpstreamError(extractKindFromPath(path), "timeout")
			lastErr = fmt.Errorf("%w: %v", ErrUpstreamUnavailable, err)
			continue
		}
		// yujiawei round-6 P2: cap the read with io.LimitReader, and
		// surface a read error as a retryable upstream blip instead
		// of falling through to json.Unmarshal which produces a
		// non-retryable terminal decode error and misattributes a
		// transient network hiccup as a contract violation.
		respBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, maxVerifyRespBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			c.col.ObserveUpstreamError(extractKindFromPath(path), "timeout")
			lastErr = fmt.Errorf("%w: read body: %v", ErrUpstreamUnavailable, readErr)
			continue
		}
		if len(respBytes) > maxVerifyRespBytes {
			c.col.ObserveUpstreamError(extractKindFromPath(path), "5xx_server")
			lastErr = fmt.Errorf("%w: response exceeds %d bytes", ErrUpstreamUnavailable, maxVerifyRespBytes)
			continue
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if err := json.Unmarshal(respBytes, respBody); err != nil {
				// yujiawei round-6 P2: a malformed 2xx body is a
				// server/contract failure, not a bad credential. Map
				// to ErrUpstreamUnavailable (which the wrappers don't
				// negative-cache) instead of letting writeError pin
				// it to AUTH_TOKEN_INVALID via the default branch.
				c.col.ObserveUpstreamError(extractKindFromPath(path), "5xx_server")
				return fmt.Errorf("%w: decode response: %v", ErrUpstreamUnavailable, err)
			}
			return nil
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest:
			// 401 and 400 are both candidates for "token invalid" because
			// octo-server pins httperr.ResponseErrorL to 400 by default
			// (legacy D14 compat per CLAUDE.md) with the real intended
			// status in error.http_status. Decode the envelope and:
			//   - if Error.Code is AUTH_BOT_UNAVAILABLE → ErrBotUnavailable.
			//   - if HTTPStatus is set and isn't 401, treat as upstream
			//     unavailable (a transient 4xx pinned to 400 should not
			//     poison the negative cache — yujiawei round-6 P2).
			//   - otherwise (genuine 401 or 400 without http_status) →
			//     ErrTokenInvalid.
			if env := decodeErrorEnvelope(respBytes); env != nil {
				if env.Error.Code == CodeBotUnavailable {
					return ErrBotUnavailable
				}
				if env.Error.HTTPStatus != 0 && env.Error.HTTPStatus != http.StatusUnauthorized && env.Error.HTTPStatus != http.StatusBadRequest {
					c.col.ObserveUpstreamError(extractKindFromPath(path), "4xx_client")
					lastErr = ErrUpstreamUnavailable
					continue
				}
			}
			return ErrTokenInvalid
		case resp.StatusCode == http.StatusServiceUnavailable:
			if env := decodeErrorEnvelope(respBytes); env != nil && env.Error.Code == CodeBotUnavailable {
				return ErrBotUnavailable
			}
			c.col.ObserveUpstreamError(extractKindFromPath(path), "5xx_server")
			lastErr = ErrUpstreamUnavailable
			continue
		case resp.StatusCode >= 500:
			c.col.ObserveUpstreamError(extractKindFromPath(path), "5xx_server")
			lastErr = ErrUpstreamUnavailable
			continue
		default:
			// Non-actionable 4xx (e.g. 403/404/429): the token is not
			// proven invalid — the server gave us a transport-shaped
			// rejection. yujiawei round-5 P2-2 review: mapping these
			// to ErrTokenInvalid plus negative-caching for the full
			// CacheTTL meant a transient 429 (rate-limit) or 404
			// (proxy/gateway route rollout) poisoned the token for up
			// to 60s. Bucket as upstream-unavailable so callers fail
			// closed on this request but the next call re-tries (the
			// VerifyUser/VerifyBot/VerifyAPIKey wrappers don't cache
			// ErrUpstreamUnavailable — only ErrTokenInvalid).
			c.col.ObserveUpstreamError(extractKindFromPath(path), "4xx_client")
			lastErr = ErrUpstreamUnavailable
			continue
		}
	}
	if lastErr == nil {
		lastErr = ErrUpstreamUnavailable
	}
	return lastErr
}

func decodeErrorEnvelope(b []byte) *contract.ErrorEnvelope {
	if len(b) == 0 {
		return nil
	}
	var env contract.ErrorEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil
	}
	if env.Error.Code == "" {
		return nil
	}
	return &env
}

func resultLabel(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, ErrTokenInvalid), errors.Is(err, ErrTokenMissing), errors.Is(err, ErrBotUnavailable):
		return "invalid"
	case errors.Is(err, ErrUpstreamUnavailable):
		return "upstream_error"
	default:
		return "upstream_error"
	}
}

func extractKindFromPath(path string) string {
	switch path {
	case "/v1/auth/verify":
		return "user"
	case "/v1/auth/verify-bot":
		return "bot"
	case "/v1/auth/verify-api-key":
		return "apikey"
	default:
		return "unknown"
	}
}

// cloneUserResp / cloneBotResp / cloneAPIKeyResp return deep copies of
// the response DTOs so cached pointers are never shared with callers.
// Jerry-Xin round-6 P0 on octo-auth#2: returning the cached pointer
// directly let any direct SDK caller (or context-injected handler)
// mutate the slice/map fields and silently corrupt the cache entry
// for every subsequent request using the same token. The middleware
// already does its own defensive copy at the context accessors
// (yujiawei round-5 P2-3), but the Client methods are the public
// SDK surface and must be safe on their own.
func cloneUserResp(in *contract.VerifyUserResp) *contract.VerifyUserResp {
	if in == nil {
		return nil
	}
	out := *in // shallow copy of scalar fields
	out.Spaces = cloneStringSlice(in.Spaces)
	out.OwnedBotsBySpace = cloneStringSliceMap(in.OwnedBotsBySpace)
	if len(in.OwnedBots) > 0 {
		out.OwnedBots = make([]contract.OwnedBot, len(in.OwnedBots))
		copy(out.OwnedBots, in.OwnedBots) // OwnedBot is a struct of scalars
	}
	return &out
}

func cloneBotResp(in *contract.VerifyBotResp) *contract.VerifyBotResp {
	if in == nil {
		return nil
	}
	out := *in // VerifyBotResp is all scalar fields
	return &out
}

func cloneAPIKeyResp(in *contract.VerifyAPIKeyResp) *contract.VerifyAPIKeyResp {
	if in == nil {
		return nil
	}
	out := *in
	out.OwnedBotsBySpace = cloneStringSliceMap(in.OwnedBotsBySpace)
	return &out
}

func cloneStringSlice(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if in == nil {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = cloneStringSlice(v)
	}
	return out
}
