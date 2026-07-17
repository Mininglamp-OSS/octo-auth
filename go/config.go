package octoauth

import (
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Default cache / timeout / TTL values used by [applyDefaults]. They are
// exported for callers who want to reference them when composing derived
// configs.
const (
	// DefaultLRUCacheSize is the default entry capacity of the built-in LRU
	// cache (~800 KiB in-mem at 80 B / entry, ample headroom for realistic
	// per-service traffic).
	DefaultLRUCacheSize = 10_000
	// DefaultHTTPTimeout is the per-verify request timeout.
	DefaultHTTPTimeout = 5 * time.Second
	// DefaultSessionTTL matches the SSO revocation window budget.
	DefaultSessionTTL = 30 * time.Second
	// DefaultBotTTL is the bot-realm cache TTL.
	DefaultBotTTL = 60 * time.Second
	// DefaultAPIKeyTTL is the api-key-realm cache TTL.
	DefaultAPIKeyTTL = 60 * time.Second
	// DefaultNegativeTTL bounds how long a rejected credential stays in cache
	// to shield octo-server from replayed invalid tokens.
	DefaultNegativeTTL = 5 * time.Second
)

// Ptr returns a pointer to v. It is a convenience for building [Config] with
// tri-state bool fields (RequestIncludeContext, HashCacheKey) where nil means
// "use default".
func Ptr[T any](v T) *T { return &v }

// Config holds the shared configuration passed to every verifier. All fields
// except BaseURL have safe defaults filled in by [applyDefaults]; callers
// only need to set BaseURL to get a working setup.
type Config struct {
	// BaseURL is the octo-server base URL, e.g. https://octo-server:8090.
	// Required; zero value is invalid.
	BaseURL string

	// HTTPClient is the transport used by every verifier. If nil, a
	// fresh &http.Client{Timeout: DefaultHTTPTimeout} is installed.
	//
	// applyDefaults enforces CheckRedirect on this client (fail-closed on
	// 3xx) even when the caller supplies their own — verify POST bodies
	// carry raw credentials, and Go's default follow-10-hops behavior
	// would replay them to a 307/308 Location. Callers who need to handle
	// redirects out-of-band must implement that outside the verify path.
	HTTPClient *http.Client

	// Cache backs verify-result memoization. If nil, an in-mem LRU sized to
	// DefaultLRUCacheSize is installed. Set to a no-op cache to disable
	// caching entirely.
	Cache Cache

	// Metrics receives telemetry callbacks. If nil, [NoopMetrics] is used.
	Metrics MetricsCollector

	// Logger is the slog handle used for internal diagnostics (cache miss,
	// verify failure, pre-v2 fallback). Never used for user-facing responses.
	// If nil, [slog.Default] is used.
	Logger *slog.Logger

	// ErrorMapper converts SDK errors into HTTP responses at the middleware
	// layer. If nil, [DefaultErrorMapper] is used.
	ErrorMapper ErrorMapperFunc

	// Per-verifier TTL knobs. Zero values fall back to the Default*TTL
	// constants above. Callers who want to disable caching for a specific
	// realm should set the corresponding TTL to a very small value (e.g.
	// 1 * time.Nanosecond) or install a no-op Cache.
	SessionTTL  time.Duration
	BotTTL      time.Duration
	APIKeyTTL   time.Duration
	NegativeTTL time.Duration

	// RequestIncludeContext controls whether the session and api-key verifiers
	// append ?include=context to their POST /v1/auth/verify(-api-key) call.
	// nil means default true; pass [Ptr]\(false\) to opt out explicitly. Bot
	// verifier ignores this field.
	RequestIncludeContext *bool

	// HashCacheKey controls whether raw tokens are SHA-256 hashed before
	// being used as cache keys. nil means default true; pass [Ptr]\(false\)
	// only for local debugging.
	HashCacheKey *bool
}

// applyDefaults mutates cfg in place to fill unset fields with the package
// defaults. It is idempotent and safe to call from every verifier
// constructor; verifiers should call it once after receiving a *Config.
//
// applyDefaults panics if cfg is nil so misconfiguration is caught at
// process start rather than on the first request.
func applyDefaults(cfg *Config) {
	if cfg == nil {
		panic("octoauth: Config must not be nil")
	}
	if cfg.HTTPClient == nil {
		// CheckRedirect returns http.ErrUseLastResponse so the client stops
		// at the first 3xx and surfaces it as an "unexpected status" =>
		// InfraFailure. Blindly following a 307/308 would replay the POST
		// body — which for verify calls contains the raw credential
		// (`{"token":"..."}`, `bf_...`, `uk_...`) — to a Location target
		// controlled by an attacker or a misconfigured reverse proxy.
		// Reviewer P1-B.
		cfg.HTTPClient = &http.Client{
			Timeout: DefaultHTTPTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	} else if cfg.HTTPClient.CheckRedirect == nil {
		// The user brought their own *http.Client but didn't override
		// CheckRedirect — Go's default is to follow up to 10 redirects.
		// Same credential-leak risk as the nil-client branch above; enforce
		// the same fail-closed policy. This mutates the caller's client
		// struct in place, which is documented on the Config.HTTPClient
		// field. Reviewer P1-F.
		cfg.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if cfg.Cache == nil {
		cfg.Cache = NewLRUCache(DefaultLRUCacheSize)
	}
	if cfg.Metrics == nil {
		cfg.Metrics = NoopMetrics{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.ErrorMapper == nil {
		cfg.ErrorMapper = DefaultErrorMapper
	}
	// TTL fields: undefined (zero) OR negative → default. Coercing negatives
	// matches the TS SDK's applyDefaults and prevents a miscalculated
	// negative duration from producing a permanent auth cache (cache.Set
	// treats ttl <= 0 as "no expiry" — see go/cache.go). Reviewer P1-D.
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultSessionTTL
	}
	if cfg.BotTTL <= 0 {
		cfg.BotTTL = DefaultBotTTL
	}
	if cfg.APIKeyTTL <= 0 {
		cfg.APIKeyTTL = DefaultAPIKeyTTL
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = DefaultNegativeTTL
	}
	if cfg.RequestIncludeContext == nil {
		cfg.RequestIncludeContext = Ptr(true)
	}
	if cfg.HashCacheKey == nil {
		cfg.HashCacheKey = Ptr(true)
	}
}

// ErrorMapperFunc converts an SDK error into an HTTP status code and response
// body. Middlewares call this exactly once per rejected request; the returned
// body is written verbatim to the response.
type ErrorMapperFunc func(err error) (statusCode int, body []byte)

// Response bodies used by [DefaultErrorMapper]. They are deliberately
// enumeration-resistant: two failure modes that map to the same status
// produce byte-identical output so an attacker cannot infer whether a token
// is unknown vs. expired vs. malformed.
var (
	bodyUnauthorized        = []byte(`{"error":"unauthorized"}`)
	bodyDisabled            = []byte(`{"error":"disabled"}`)
	bodyUpstreamUnavailable = []byte(`{"error":"upstream_unavailable"}`)
	bodyForbidden           = []byte(`{"error":"forbidden"}`)
	bodyInternal            = []byte(`{"error":"internal"}`)
)

// DefaultErrorMapper implements the reference status / body table:
//
//	ErrKindInvalidCredential → 401 {"error":"unauthorized"}
//	ErrKindDisabled          → 403 {"error":"disabled"}
//	ErrKindInfraFailure      → 503 {"error":"upstream_unavailable"}
//	ErrKindForbidden         → 403 {"error":"forbidden"}
//	otherwise                → 500 {"error":"internal"}
//
// Non-SDK errors and ErrKindPreV2Server both fall through to the 500 branch
// — pre-v2 signals are handled inside verifiers and should never reach the
// mapper.
func DefaultErrorMapper(err error) (int, []byte) {
	var authErr *Error
	if !errors.As(err, &authErr) {
		return http.StatusInternalServerError, bodyInternal
	}
	switch authErr.Kind {
	case ErrKindInvalidCredential:
		return http.StatusUnauthorized, bodyUnauthorized
	case ErrKindDisabled:
		return http.StatusForbidden, bodyDisabled
	case ErrKindInfraFailure:
		return http.StatusServiceUnavailable, bodyUpstreamUnavailable
	case ErrKindForbidden:
		return http.StatusForbidden, bodyForbidden
	default:
		return http.StatusInternalServerError, bodyInternal
	}
}
