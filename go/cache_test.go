package octoauth

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashCacheKeyDeterministic(t *testing.T) {
	a := HashCacheKey("hello")
	b := HashCacheKey("hello")
	assert.Equal(t, a, b, "HashCacheKey must be deterministic")
	assert.Len(t, a, 64, "SHA-256 hex output is 64 chars")

	c := HashCacheKey("world")
	assert.NotEqual(t, a, c)
	// A known SHA-256 vector for "hello".
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", a)
}

func TestLRUCacheBasic(t *testing.T) {
	c := NewLRUCache(4)
	ctx := context.Background()

	// Miss on empty cache.
	_, ok := c.Get(ctx, "k1")
	assert.False(t, ok)

	// Set + Get roundtrip.
	c.Set(ctx, "k1", "v1", time.Minute)
	v, ok := c.Get(ctx, "k1")
	require.True(t, ok)
	assert.Equal(t, "v1", v)

	// Overwrite.
	c.Set(ctx, "k1", "v2", time.Minute)
	v, ok = c.Get(ctx, "k1")
	require.True(t, ok)
	assert.Equal(t, "v2", v)

	// Delete.
	c.Delete(ctx, "k1")
	_, ok = c.Get(ctx, "k1")
	assert.False(t, ok)

	// Delete of missing key is a no-op.
	c.Delete(ctx, "does-not-exist")
}

func TestLRUCacheTTLExpiry(t *testing.T) {
	c := NewLRUCache(4)
	ctx := context.Background()

	c.Set(ctx, "short", "value", 10*time.Millisecond)
	v, ok := c.Get(ctx, "short")
	require.True(t, ok)
	assert.Equal(t, "value", v)

	time.Sleep(20 * time.Millisecond)

	_, ok = c.Get(ctx, "short")
	assert.False(t, ok, "expired entry must be reported as miss")
}

func TestLRUCacheZeroTTLNoExpiry(t *testing.T) {
	c := NewLRUCache(4)
	ctx := context.Background()

	c.Set(ctx, "forever", "value", 0)
	time.Sleep(10 * time.Millisecond)

	v, ok := c.Get(ctx, "forever")
	require.True(t, ok, "ttl=0 must mean no expiry")
	assert.Equal(t, "value", v)
}

func TestLRUCacheEviction(t *testing.T) {
	c := NewLRUCache(2)
	ctx := context.Background()

	c.Set(ctx, "a", 1, time.Minute)
	c.Set(ctx, "b", 2, time.Minute)
	c.Set(ctx, "c", 3, time.Minute) // triggers eviction of oldest

	_, ok := c.Get(ctx, "a")
	assert.False(t, ok, "oldest entry must be evicted at capacity")

	v, ok := c.Get(ctx, "c")
	require.True(t, ok)
	assert.Equal(t, 3, v)
}

func TestLRUCacheEvictionRefreshesOnGet(t *testing.T) {
	c := NewLRUCache(2)
	ctx := context.Background()

	c.Set(ctx, "a", 1, time.Minute)
	c.Set(ctx, "b", 2, time.Minute)
	// Touching "a" makes "b" the LRU entry.
	_, _ = c.Get(ctx, "a")
	c.Set(ctx, "c", 3, time.Minute)

	_, ok := c.Get(ctx, "b")
	assert.False(t, ok, "b should be evicted after a was touched")
	_, ok = c.Get(ctx, "a")
	assert.True(t, ok)
}

func TestNewLRUCachePanicsOnNonPositive(t *testing.T) {
	assert.Panics(t, func() { NewLRUCache(0) })
	assert.Panics(t, func() { NewLRUCache(-1) })
}

func TestLRUCacheStoresNilValue(t *testing.T) {
	c := NewLRUCache(4)
	ctx := context.Background()
	c.Set(ctx, "n", nil, time.Minute)
	v, ok := c.Get(ctx, "n")
	require.True(t, ok, "nil is a legitimate cached value (used for negative results)")
	assert.Nil(t, v)
}
