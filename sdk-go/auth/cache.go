package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// cachedIdentity is the polymorphic value the cache stores. Exactly one
// of the three pointer fields is non-nil; ResultErr captures the
// terminal sentinel (ErrTokenInvalid / ErrBotUnavailable) for negative
// cache entries.
type cachedIdentity struct {
	UserResp   any // *contract.VerifyUserResp
	BotResp    any // *contract.VerifyBotResp
	APIKeyResp any // *contract.VerifyAPIKeyResp
	ResultErr  error
	StoredAt   time.Time
}

// verifyCache wraps a hashicorp/golang-lru/v2 with SHA-256 keying and
// TTL eviction. The LRU itself enforces the capacity bound; TTL is
// checked at Get time (no background sweeper — we don't want goroutine
// management for an in-process cache).
type verifyCache struct {
	mu       sync.Mutex
	store    *lru.Cache[string, *cachedIdentity]
	ttl      time.Duration
	now      func() time.Time
	collect  cacheMetricsHook
}

// cacheMetricsHook is the subset of metrics.Collector verifyCache uses.
// Decoupled so cache_test.go doesn't need to import metrics.
type cacheMetricsHook interface {
	ObserveCacheHit(kind string)
	ObserveCacheEvict(reason string)
}

func newVerifyCache(maxSize int, ttl time.Duration, hook cacheMetricsHook) (*verifyCache, error) {
	c, err := lru.NewWithEvict(maxSize, func(_ string, _ *cachedIdentity) {
		// LRU eviction is always capacity-driven (the only way an item
		// leaves the LRU is when it's pushed off). TTL evictions happen
		// implicitly via the Get-time staleness check.
		if hook != nil {
			hook.ObserveCacheEvict("capacity")
		}
	})
	if err != nil {
		return nil, err
	}
	return &verifyCache{store: c, ttl: ttl, now: time.Now, collect: hook}, nil
}

// key returns the SHA-256 cache key for a (kind, token) pair. The raw
// token never reaches the cache — only its digest is stored, so a heap
// dump can't leak tokens.
func cacheKey(kind, token string) string {
	h := sha256.Sum256([]byte(kind + ":" + token))
	return hex.EncodeToString(h[:])
}

// Get returns (entry, true) on hit, (nil, false) on miss-or-stale. A
// stale entry is removed eagerly so the next Get incurs only one
// lookup.
func (vc *verifyCache) Get(kind, token string) (*cachedIdentity, bool) {
	k := cacheKey(kind, token)
	vc.mu.Lock()
	defer vc.mu.Unlock()
	entry, ok := vc.store.Get(k)
	if !ok {
		return nil, false
	}
	if vc.now().Sub(entry.StoredAt) >= vc.ttl {
		vc.store.Remove(k)
		if vc.collect != nil {
			vc.collect.ObserveCacheEvict("ttl")
		}
		return nil, false
	}
	if vc.collect != nil {
		vc.collect.ObserveCacheHit(kind)
	}
	return entry, true
}

// Set stores an entry. Negative cache entries (ResultErr != nil) are
// stored just like positive ones — TTL applies — so a transient
// ErrTokenInvalid can't keep failing forever after the token is
// re-issued.
func (vc *verifyCache) Set(kind, token string, entry *cachedIdentity) {
	entry.StoredAt = vc.now()
	k := cacheKey(kind, token)
	vc.mu.Lock()
	vc.store.Add(k, entry)
	vc.mu.Unlock()
}

// Len returns the current entry count. Used for the cache_size gauge.
func (vc *verifyCache) Len() int {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	return vc.store.Len()
}

// Purge wipes the cache. Exposed for tests and for an emergency
// "drop all cached identities" hook callers may want during a known
// security incident.
func (vc *verifyCache) Purge() {
	vc.mu.Lock()
	n := vc.store.Len()
	vc.store.Purge()
	vc.mu.Unlock()
	if vc.collect != nil {
		for i := 0; i < n; i++ {
			vc.collect.ObserveCacheEvict("manual")
		}
	}
}
