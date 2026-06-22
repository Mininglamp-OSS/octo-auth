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
func (c *Client) VerifyUser(ctx context.Context, token string, includeContext bool) (*contract.VerifyUserResp, error) {
	const kind = "user"
	if entry, ok := c.cache.Get(kind, token, includeContext); ok {
		c.col.ObserveVerify(kind, "cache_hit", 0)
		if entry.ResultErr != nil {
			return nil, entry.ResultErr
		}
		return entry.UserResp.(*contract.VerifyUserResp), nil
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
	return &resp, nil
}

// VerifyBot verifies a bot token (bf_ for User Bot, app_ for App Bot).
// Bot verify does not take an includeContext flag — the bot response
// shape is fixed at the contract level — so cache uses includeContext=false
// consistently for the bot kind.
func (c *Client) VerifyBot(ctx context.Context, botToken string) (*contract.VerifyBotResp, error) {
	const kind = "bot"
	if entry, ok := c.cache.Get(kind, botToken, false); ok {
		c.col.ObserveVerify(kind, "cache_hit", 0)
		if entry.ResultErr != nil {
			return nil, entry.ResultErr
		}
		return entry.BotResp.(*contract.VerifyBotResp), nil
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
	return &resp, nil
}

// VerifyAPIKey verifies a uk_ API key.
func (c *Client) VerifyAPIKey(ctx context.Context, apiKey string, includeContext bool) (*contract.VerifyAPIKeyResp, error) {
	const kind = "apikey"
	if entry, ok := c.cache.Get(kind, apiKey, includeContext); ok {
		c.col.ObserveVerify(kind, "cache_hit", 0)
		if entry.ResultErr != nil {
			return nil, entry.ResultErr
		}
		return entry.APIKeyResp.(*contract.VerifyAPIKeyResp), nil
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
	return &resp, nil
}

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
			// Timeout / network — bucket as "timeout"
			c.col.ObserveUpstreamError(extractKindFromPath(path), "timeout")
			lastErr = fmt.Errorf("%w: %v", ErrUpstreamUnavailable, err)
			continue
		}
		respBytes, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if err := json.Unmarshal(respBytes, respBody); err != nil {
				return fmt.Errorf("octoauth: decode response: %w", err)
			}
			return nil
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest:
			// 401 and 400 are both treated as "token invalid" — octo-server
			// pins httperr.ResponseErrorL to 400 by default (legacy
			// D14 compatibility per CLAUDE.md) with the real intended
			// status in error.http_status. Decode the envelope if present
			// to surface bot-unavailable correctly.
			if env := decodeErrorEnvelope(respBytes); env != nil && env.Error.Code == CodeBotUnavailable {
				return ErrBotUnavailable
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
			c.col.ObserveUpstreamError(extractKindFromPath(path), "4xx_client")
			return ErrTokenInvalid
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
