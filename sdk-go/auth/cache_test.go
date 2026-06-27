package auth

import (
	"testing"
	"time"
)

// noopHook satisfies cacheMetricsHook without state.
type noopHook struct{}

func (noopHook) ObserveCacheHit(string)   {}
func (noopHook) ObserveCacheEvict(string) {}

// countingHook captures per-reason eviction counts so the
// double-counting regression yujiawei flagged on octo-auth#2 can't
// silently come back.
type countingHook struct {
	hits        map[string]int
	evictsByRsn map[string]int
}

func newCountingHook() *countingHook {
	return &countingHook{hits: map[string]int{}, evictsByRsn: map[string]int{}}
}
func (c *countingHook) ObserveCacheHit(kind string)   { c.hits[kind]++ }
func (c *countingHook) ObserveCacheEvict(reason string) {
	c.evictsByRsn[reason]++
}

// TestCacheKeyIsSHA256 pins the security-critical invariant: the cache
// stores a SHA-256 digest of (kind+":"+ctxBit+":"+token), NEVER the raw
// token. A heap-dump of the SDK process must not leak tokens.
func TestCacheKeyIsSHA256(t *testing.T) {
	t.Parallel()
	got := cacheKey("user", "secret-token-abc", false)
	if got == "user:secret-token-abc" || got == "user:0:secret-token-abc" {
		t.Fatal("cacheKey leaked raw token into the key")
	}
	if len(got) != 64 {
		t.Fatalf("cacheKey output length = %d, want 64 (hex SHA-256)", len(got))
	}
	// Determinism: same input → same key.
	if cacheKey("user", "secret-token-abc", false) != got {
		t.Fatal("cacheKey not deterministic")
	}
	// Kind separation: different kind → different key.
	if cacheKey("bot", "secret-token-abc", false) == got {
		t.Fatal("cacheKey collapsed kind+token; bot and user must not collide")
	}
	// includeContext separation (yujiawei P1 review on octo-auth#2):
	// no-context and context-included entries MUST NOT share a slot —
	// otherwise RequireSpaceMember silently downgrades to compat mode.
	if cacheKey("user", "secret-token-abc", true) == got {
		t.Fatal("cacheKey ignored includeContext; no-context and context-included entries would collide")
	}
}

func TestCacheGetSet(t *testing.T) {
	t.Parallel()
	c, err := newVerifyCache(10, time.Hour, noopHook{})
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	if _, ok := c.Get("user", "absent", false); ok {
		t.Fatal("Get on empty cache must miss")
	}
	c.Set("user", "t1", false, &cachedIdentity{UserResp: "marker"})
	entry, ok := c.Get("user", "t1", false)
	if !ok || entry.UserResp.(string) != "marker" {
		t.Fatalf("Get after Set: ok=%v entry=%+v", ok, entry)
	}
	// includeContext separation at the Get level: same token, different
	// includeContext flag, MUST miss.
	if _, ok := c.Get("user", "t1", true); ok {
		t.Fatal("Get(includeContext=true) on no-context entry must miss")
	}
}

func TestCacheTTLEviction(t *testing.T) {
	t.Parallel()
	hook := newCountingHook()
	c, err := newVerifyCache(10, 50*time.Millisecond, hook)
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	now := time.Unix(0, 0)
	c.now = func() time.Time { return now }
	c.Set("user", "t1", false, &cachedIdentity{UserResp: "x"})
	now = now.Add(100 * time.Millisecond) // past TTL
	if _, ok := c.Get("user", "t1", false); ok {
		t.Fatal("stale entry must not return as hit")
	}
	if c.Len() != 0 {
		t.Fatalf("stale entry not evicted: len=%d", c.Len())
	}
	// Eviction-metric attribution (yujiawei P2 review): the TTL
	// eviction must count as "ttl", not "capacity". The OnEvict-
	// suppression flag is what makes this work.
	if hook.evictsByRsn["ttl"] != 1 {
		t.Fatalf("ttl evict count = %d, want 1", hook.evictsByRsn["ttl"])
	}
	if hook.evictsByRsn["capacity"] != 0 {
		t.Fatalf("capacity evict count = %d, want 0 (would indicate double-counting)", hook.evictsByRsn["capacity"])
	}
}

func TestCacheCapacityEviction(t *testing.T) {
	t.Parallel()
	hook := newCountingHook()
	c, err := newVerifyCache(2, time.Hour, hook)
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	c.Set("user", "a", false, &cachedIdentity{UserResp: "1"})
	c.Set("user", "b", false, &cachedIdentity{UserResp: "2"})
	c.Set("user", "c", false, &cachedIdentity{UserResp: "3"}) // evicts a
	if c.Len() != 2 {
		t.Fatalf("expected len=2 after capacity eviction, got %d", c.Len())
	}
	if _, ok := c.Get("user", "a", false); ok {
		t.Fatal("a should have been LRU-evicted by c")
	}
	if hook.evictsByRsn["capacity"] != 1 {
		t.Fatalf("capacity evict count = %d, want 1", hook.evictsByRsn["capacity"])
	}
}

func TestCachePurge(t *testing.T) {
	t.Parallel()
	hook := newCountingHook()
	c, err := newVerifyCache(10, time.Hour, hook)
	if err != nil {
		t.Fatalf("newVerifyCache: %v", err)
	}
	c.Set("user", "a", false, &cachedIdentity{UserResp: "1"})
	c.Set("user", "b", false, &cachedIdentity{UserResp: "2"})
	c.Purge()
	if c.Len() != 0 {
		t.Fatalf("after purge len=%d", c.Len())
	}
	// Purge MUST attribute as "manual" exactly n times (n=2 here), NOT
	// as "capacity" (yujiawei P2 review: pre-fix Purge double-counted
	// because OnEvict also fired). suppressOE prevents that.
	if hook.evictsByRsn["manual"] != 2 {
		t.Fatalf("manual evict count = %d, want 2", hook.evictsByRsn["manual"])
	}
	if hook.evictsByRsn["capacity"] != 0 {
		t.Fatalf("capacity evict count = %d, want 0 (would indicate double-counting)", hook.evictsByRsn["capacity"])
	}
}
