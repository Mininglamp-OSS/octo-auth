package auth

import (
	"testing"
	"time"
)

// noopHook satisfies cacheMetricsHook without state.
type noopHook struct{}

func (noopHook) ObserveCacheHit(string)    {}
func (noopHook) ObserveCacheEvict(string)  {}

// TestCacheKeyIsSHA256 pins the security-critical invariant: the cache
// stores a SHA-256 digest of (kind+":"+token), NEVER the raw token. A
// heap-dump of the SDK process must not leak tokens.
func TestCacheKeyIsSHA256(t *testing.T) {
	t.Parallel()
	got := cacheKey("user", "secret-token-abc")
	if got == "user:secret-token-abc" {
		t.Fatal("cacheKey leaked raw token into the key")
	}
	if len(got) != 64 {
		t.Fatalf("cacheKey output length = %d, want 64 (hex SHA-256)", len(got))
	}
	// Determinism: same input → same key.
	if cacheKey("user", "secret-token-abc") != got {
		t.Fatal("cacheKey not deterministic")
	}
	// Kind separation: different kind → different key.
	if cacheKey("bot", "secret-token-abc") == got {
		t.Fatal("cacheKey collapsed kind+token; bot and user must not collide")
	}
}

func TestCacheGetSet(t *testing.T) {
	t.Parallel()
	c, err := newVerifyCache(10, time.Hour, noopHook{})
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	if _, ok := c.Get("user", "absent"); ok {
		t.Fatal("Get on empty cache must miss")
	}
	c.Set("user", "t1", &cachedIdentity{UserResp: "marker"})
	entry, ok := c.Get("user", "t1")
	if !ok || entry.UserResp.(string) != "marker" {
		t.Fatalf("Get after Set: ok=%v entry=%+v", ok, entry)
	}
}

func TestCacheTTLEviction(t *testing.T) {
	t.Parallel()
	c, err := newVerifyCache(10, 50*time.Millisecond, noopHook{})
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	// Override clock for deterministic test.
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	c.Set("user", "t1", &cachedIdentity{UserResp: "x"})
	now = now.Add(100 * time.Millisecond) // past TTL
	if _, ok := c.Get("user", "t1"); ok {
		t.Fatal("stale entry must not return as hit")
	}
	// Stale entry must have been removed.
	if c.Len() != 0 {
		t.Fatalf("stale entry not evicted: len=%d", c.Len())
	}
}

func TestCacheCapacityEviction(t *testing.T) {
	t.Parallel()
	c, err := newVerifyCache(2, time.Hour, noopHook{})
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	c.Set("user", "a", &cachedIdentity{UserResp: "1"})
	c.Set("user", "b", &cachedIdentity{UserResp: "2"})
	c.Set("user", "c", &cachedIdentity{UserResp: "3"}) // evicts a
	if c.Len() != 2 {
		t.Fatalf("expected len=2 after capacity eviction, got %d", c.Len())
	}
	if _, ok := c.Get("user", "a"); ok {
		t.Fatal("a should have been LRU-evicted by c")
	}
}

func TestCachePurge(t *testing.T) {
	t.Parallel()
	c, err := newVerifyCache(10, time.Hour, noopHook{})
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	c.Set("user", "a", &cachedIdentity{UserResp: "1"})
	c.Set("user", "b", &cachedIdentity{UserResp: "2"})
	c.Purge()
	if c.Len() != 0 {
		t.Fatalf("after purge len=%d", c.Len())
	}
}
