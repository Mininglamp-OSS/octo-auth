package octoauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// Cache is the pluggable cache backend used by verifiers to memoize verify
// results and negative outcomes. Implementations must be safe for concurrent
// use and MUST honor the per-entry ttl passed to [Cache.Set] — verifiers
// depend on TTL to bound the SSO revocation window (design doc §6).
//
// A ttl of zero means "no expiry"; verifiers do not use that path but
// implementations should accept it gracefully.
type Cache interface {
	// Get returns the cached value and ok=true when present and not expired.
	// A ctx-driven cancellation should short-circuit blocking backends;
	// in-mem backends may ignore ctx.
	Get(ctx context.Context, key string) (value any, ok bool)
	// Set stores value under key with the given ttl.
	Set(ctx context.Context, key string, value any, ttl time.Duration)
	// Delete removes key. It is not an error to delete a missing key.
	Delete(ctx context.Context, key string)
}

// HashCacheKey returns the SHA-256 hex digest of raw. Verifiers call this
// (when [Config.HashCacheKey] is true) so that raw session / bot / api-key
// tokens never appear verbatim inside cache keys, matching the pattern used
// by octo-matter's octoim cache. See design doc §4.1 / §6.
//
// The returned string is 64 lowercase hex characters and is deterministic.
func HashCacheKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// lruEntry wraps a cached value with an absolute expiry timestamp. A zero
// expiresAt means "never expires" (ttl == 0 path).
type lruEntry struct {
	value     any
	expiresAt time.Time
}

// LRUCache is the default in-mem [Cache] implementation. It wraps
// hashicorp/golang-lru/v2 with per-entry TTL semantics on top of the LRU
// eviction policy.
//
// The zero value is not usable; construct via [NewLRUCache].
type LRUCache struct {
	mu    sync.Mutex
	inner *lru.Cache[string, lruEntry]
}

// NewLRUCache builds an [LRUCache] bounded to maxSize entries. maxSize must
// be > 0; the constructor panics on non-positive input to fail fast during
// startup, matching the golang-lru upstream contract.
func NewLRUCache(maxSize int) Cache {
	if maxSize <= 0 {
		panic("octoauth: LRU cache size must be > 0")
	}
	c, err := lru.New[string, lruEntry](maxSize)
	if err != nil {
		// lru.New only errors on non-positive size, which we already guarded.
		panic("octoauth: LRU cache init failed: " + err.Error())
	}
	return &LRUCache{inner: c}
}

// Get returns the cached value if present and not expired. Expired entries
// are evicted lazily on read.
func (c *LRUCache) Get(_ context.Context, key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.inner.Get(key)
	if !ok {
		return nil, false
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		c.inner.Remove(key)
		return nil, false
	}
	return entry.value, true
}

// Set stores value under key. A ttl <= 0 stores the entry without expiry.
func (c *LRUCache) Set(_ context.Context, key string, value any, ttl time.Duration) {
	entry := lruEntry{value: value}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inner.Add(key, entry)
}

// Delete removes key. Missing keys are ignored.
func (c *LRUCache) Delete(_ context.Context, key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inner.Remove(key)
}
