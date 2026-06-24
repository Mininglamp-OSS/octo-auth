package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Mininglamp-OSS/octo-auth/sdk-go/contract"
)

// newTestServer returns an httptest.Server that responds to verify
// requests with the supplied handler. Tests construct a Client that
// targets this server and exercise the full Marshal → HTTP → decode
// → cache flow.
func newTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestClientVerifyUserOK(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/verify" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		var req contract.VerifyUserReq
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != "user-tok-1" {
			t.Errorf("token mismatch: %q", req.Token)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion: 1, Kind: "user", UID: "u1", Name: "alice", Role: "admin",
		})
	})
	c, err := New(Options{ServerURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resp, err := c.VerifyUser(context.Background(), "user-tok-1", false)
	if err != nil {
		t.Fatalf("VerifyUser: %v", err)
	}
	if resp.UID != "u1" || resp.Name != "alice" || resp.Role != "admin" {
		t.Fatalf("identity mismatch: %+v", resp)
	}
}

func TestClientVerifyUserCacheHit(t *testing.T) {
	t.Parallel()
	calls := 0
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion: 1, Kind: "user", UID: "u1",
		})
	})
	c, err := New(Options{ServerURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.VerifyUser(context.Background(), "tok", false); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("server hit %d times; expected exactly 1 (rest from cache)", calls)
	}
}

func TestClientVerifyUserTokenInvalid(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(contract.ErrorEnvelope{
			SchemaVersion: 1,
			Error:         contract.Error{Code: CodeTokenInvalid, Message: "nope"},
		})
	})
	c, err := New(Options{ServerURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.VerifyUser(context.Background(), "bad-tok", false)
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("want ErrTokenInvalid, got %v", err)
	}
}

func TestClientVerifyBotAppUnavailable(t *testing.T) {
	t.Parallel()
	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(contract.ErrorEnvelope{
			SchemaVersion: 1,
			Error:         contract.Error{Code: CodeBotUnavailable, Message: "unpublished"},
		})
	})
	c, err := New(Options{ServerURL: srv.URL, MaxRetries: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.VerifyBot(context.Background(), "app_x")
	if !errors.Is(err, ErrBotUnavailable) {
		t.Fatalf("want ErrBotUnavailable, got %v", err)
	}
}

func TestClientVerifyUpstream5xxRetriesThenFails(t *testing.T) {
	t.Parallel()
	calls := 0
	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	})
	c, err := New(Options{ServerURL: srv.URL, MaxRetries: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = c.VerifyUser(context.Background(), "tok", false)
	if !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("want ErrUpstreamUnavailable, got %v", err)
	}
	// MaxRetries=2 means the SDK should attempt 1+2 = 3 times before
	// giving up.
	if calls != 3 {
		t.Fatalf("expected 3 upstream attempts, got %d", calls)
	}
}

// TestClientUpstream5xxNotCached pins the security invariant: a 5xx
// failure must NOT be cached. Caching a transient outage would extend
// the failure window beyond TTL and look like a denial-of-service to
// the caller. We exercise this by hitting an always-500 server twice
// and asserting that the upstream is hit on each call (1+MaxRetries
// times per call), not short-circuited from cache.
func TestClientUpstream5xxNotCached(t *testing.T) {
	t.Parallel()
	calls := 0
	srv := newTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	})
	c, err := New(Options{ServerURL: srv.URL, MaxRetries: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.VerifyUser(context.Background(), "tok", false); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("first call: want ErrUpstreamUnavailable, got %v", err)
	}
	if _, err := c.VerifyUser(context.Background(), "tok", false); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("second call: want ErrUpstreamUnavailable, got %v", err)
	}
	// 2 user calls × (1 initial + 1 retry) = 4 server hits. If the
	// 5xx had been cached, the second user call would have skipped
	// the upstream entirely (hits would be 2).
	if calls != 4 {
		t.Fatalf("upstream not hit per call after 5xx; calls=%d (cache leaked failure)", calls)
	}
}

func TestNewServerURLRequired(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("expected error for empty ServerURL")
	}
}

// TestClientVerifyUser4xxNotPoisonedInCache pins yujiawei round-5
// P2-2 on octo-auth#2: a transient 429 (rate-limit) or 404 (proxy
// rollout) used to map to ErrTokenInvalid and stick in the negative
// cache for up to CacheTTL (60s default), so a valid token would
// 401 for a minute after one bad upstream blip. Round-6 buckets
// those as ErrUpstreamUnavailable, which is NOT negative-cached;
// the next call retries the upstream.
func TestClientVerifyUser4xxNotPoisonedInCache(t *testing.T) {
	t.Parallel()
	var hits int32
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/verify", func(w http.ResponseWriter, _ *http.Request) {
		// First call: simulate 429 rate-limit from a gateway proxy.
		// Second call: token is genuinely valid — must NOT come back
		// First 2 calls: simulate sustained 429 rate-limit from a
		// gateway proxy (more than MaxRetries=1 so the retry path
		// also returns 429, exhausting retries → ErrUpstreamUnavailable).
		// Third call (the user retry): token is genuinely valid —
		// must NOT come back as ErrTokenInvalid from a poisoned
		// cache entry.
		atomicInc(&hits)
		if loadInt32(&hits) <= 2 {
			http.Error(w, `{"error":{"code":"RATE_LIMITED","message":"slow down"}}`, http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion: 1, Kind: "user", UID: "u1", Name: "Alice",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL, MaxRetries: 1})

	// First call: expect ErrUpstreamUnavailable, NOT ErrTokenInvalid.
	_, err := c.VerifyUser(context.Background(), "tok-X", false)
	if err == nil || !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("first call: want ErrUpstreamUnavailable on 429, got %v", err)
	}

	// Second call: must succeed (cache did NOT poison the token).
	resp, err := c.VerifyUser(context.Background(), "tok-X", false)
	if err != nil {
		t.Fatalf("second call must succeed (cache poisoning), got %v", err)
	}
	if resp.UID != "u1" {
		t.Fatalf("got UID=%q want u1", resp.UID)
	}
}

// atomicInc/loadInt32 — tiny helpers to keep the test self-contained
// without pulling sync/atomic imports into the test file's main package.
// Using local vars + a mutex would also work; mutex omitted because the
// httptest server serializes each handler invocation per connection,
// and we make sequential calls.
var int32Lock sync.Mutex

func atomicInc(p *int32) {
	int32Lock.Lock()
	defer int32Lock.Unlock()
	*p++
}
func loadInt32(p *int32) int32 {
	int32Lock.Lock()
	defer int32Lock.Unlock()
	return *p
}
