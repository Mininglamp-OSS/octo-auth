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
//
// Eviction-metric attribution: the LRU's OnEvict callback fires for
// every removal — capacity push-out, manual Remove(), AND Purge(). To
// keep the per-reason counter honest we set suppressOE to true around
// our own Remove/Purge calls; the OnEvict closure observes that flag
// and skips its metric attribution when set. Net effect: OnEvict's
// "capacity" counter only counts genuine LRU push-outs, the "ttl"
// counter only counts TTL evictions, and the "manual" counter only
// counts Purge calls (OctoBoooot review on octo-auth#2).
type verifyCache struct {
	mu         sync.Mutex
	store      *lru.Cache[string, *cachedIdentity]
	ttl        time.Duration
	now        func() time.Time
	collect    cacheMetricsHook
	suppressOE bool // when true, the OnEvict callback skips metric attribution
}

// cacheMetricsHook is the subset of metrics.Collector verifyCache uses.
// Decoupled so cache_test.go doesn't need to import metrics.
type cacheMetricsHook interface {
	ObserveCacheHit(kind string)
	ObserveCacheEvict(reason string)
}

func newVerifyCache(maxSize int, ttl time.Duration, hook cacheMetricsHook) (*verifyCache, error) {
	vc := &verifyCache{ttl: ttl, now: time.Now, collect: hook}
	c, err := lru.NewWithEvict(maxSize, func(_ string, _ *cachedIdentity) {
		// OnEvict fires for ALL removal paths (capacity push-out, our own
		// Remove for TTL, our own Purge). Only attribute to "capacity"
		// when we did NOT initiate the removal ourselves — i.e. when
		// suppressOE is false. The TTL and manual paths set
		// suppressOE=true around their store.Remove / store.Purge calls.
		if vc.suppressOE {
			return
		}
		if hook != nil {
			hook.ObserveCacheEvict("capacity")
		}
	})
	if err != nil {
		return nil, err
	}
	vc.store = c
	return vc, nil
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
		// Suppress the OnEvict attribution: we'll report "ttl" ourselves.
		vc.suppressOE = true
		vc.store.Remove(k)
		vc.suppressOE = false
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
// security incident. Suppresses the OnEvict callback's "capacity"
// attribution so each removal is reported once as "manual" rather
// than twice (once as capacity, once as manual).
func (vc *verifyCache) Purge() {
	vc.mu.Lock()
	n := vc.store.Len()
	vc.suppressOE = true
	vc.store.Purge()
	vc.suppressOE = false
	vc.mu.Unlock()
	if vc.collect != nil {
		for i := 0; i < n; i++ {
			vc.collect.ObserveCacheEvict("manual")
		}
	}
}
