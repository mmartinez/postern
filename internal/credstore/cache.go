package credstore

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mmartinez/postern/internal/broker"
)

// CachedResolver wraps a broker.Resolver with a fixed-TTL LRU cache. It is
// safe for concurrent use. Errors are propagated and never cached, so a
// transient backend failure does not stick. Whether a given reference may be
// cached at all is delegated to the shouldCache predicate the caller supplies
// (built from the credstore registry, so each vendor owns its own
// non-cacheable-ref rule); references the predicate rejects always hit the
// underlying resolver so their value stays current.
type CachedResolver struct {
	inner       broker.Resolver
	ttl         time.Duration
	now         func() time.Time
	cap         int
	shouldCache func(secretRef string) bool

	mu    sync.Mutex
	lru   *list.List
	cache map[string]*list.Element
}

// cachedEntry pairs a resolved value with its insertion time so the cache
// can evict on TTL and so the LRU list can locate the cache key on eviction.
type cachedEntry struct {
	key       string
	value     string
	expiresAt time.Time
}

// NewCachedResolver wraps inner with an LRU+TTL cache of the given capacity.
// ttl and capacity must be positive. now defaults to time.Now when nil; tests
// inject a fixed clock to exercise expiry. shouldCache decides per reference
// whether a value may be cached and is required: a nil predicate is rejected
// so a caller cannot accidentally cache a value (such as a one-time password)
// that must never be reused.
func NewCachedResolver(inner broker.Resolver, capacity int, ttl time.Duration, now func() time.Time, shouldCache func(secretRef string) bool) (*CachedResolver, error) {
	if inner == nil {
		return nil, errors.New("inner resolver is required")
	}
	if capacity <= 0 {
		return nil, errors.New("capacity must be positive")
	}
	if ttl <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	if shouldCache == nil {
		return nil, errors.New("shouldCache predicate is required")
	}
	if now == nil {
		now = time.Now
	}
	return &CachedResolver{
		inner:       inner,
		ttl:         ttl,
		now:         now,
		cap:         capacity,
		shouldCache: shouldCache,
		lru:         list.New(),
		cache:       make(map[string]*list.Element, capacity),
	}, nil
}

// Resolve returns the credential for (vaultID, secretRef), serving from cache
// when warm and not expired. References the shouldCache predicate rejects
// always hit inner so the returned value is current.
func (c *CachedResolver) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	if !c.shouldCache(secretRef) {
		v, err := c.inner.Resolve(ctx, vaultID, secretRef)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", secretRef, err)
		}
		return v, nil
	}

	k := cacheKey(vaultID, secretRef)

	c.mu.Lock()
	if el, ok := c.cache[k]; ok {
		entry := el.Value.(*cachedEntry)
		if c.now().Before(entry.expiresAt) {
			c.lru.MoveToFront(el)
			value := entry.value
			c.mu.Unlock()
			return value, nil
		}
		// expired; drop and fall through to re-resolve
		c.lru.Remove(el)
		delete(c.cache, k)
	}
	c.mu.Unlock()

	v, err := c.inner.Resolve(ctx, vaultID, secretRef)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", secretRef, err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check in case another goroutine populated the key while we were
	// blocked on inner.Resolve; if so the existing entry wins.
	if el, ok := c.cache[k]; ok {
		c.lru.MoveToFront(el)
		return el.Value.(*cachedEntry).value, nil
	}
	entry := &cachedEntry{key: k, value: v, expiresAt: c.now().Add(c.ttl)}
	el := c.lru.PushFront(entry)
	c.cache[k] = el
	if c.lru.Len() > c.cap {
		oldest := c.lru.Back()
		if oldest != nil {
			c.lru.Remove(oldest)
			delete(c.cache, oldest.Value.(*cachedEntry).key)
		}
	}
	return v, nil
}

func cacheKey(vaultID, secretRef string) string {
	return vaultID + "\x00" + secretRef
}
