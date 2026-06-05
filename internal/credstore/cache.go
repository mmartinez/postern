package credstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/mmartinez/postern/internal/broker"
)

// Backoff and background-refresh bounds. Backoff grows from baseBackoff,
// doubling per consecutive failure, capped at maxBackoff. A background refresh
// runs on a context detached from the request with refreshTimeout so a hung
// vault call cannot leak a goroutine for the process lifetime.
const (
	baseBackoff    = time.Second
	maxBackoff     = 5 * time.Minute
	refreshTimeout = 30 * time.Second
)

// errEmptyCredential marks a resolve that returned ("", nil). An empty value is
// never a usable credential (the inject path rejects it), so the cache treats
// it as a failure: it is not stored, so a deleted or misconfigured secret is
// not cached as a "fresh" blank and is retried under backoff rather than served.
var errEmptyCredential = errors.New("resolver returned an empty credential")

// CacheConfig configures a CachedResolver. TTL, RefreshAhead and MaxStale must
// satisfy 0 < RefreshAhead < TTL <= MaxStale; the config package resolves the
// effective values (and their defaults) before constructing the cache, so the
// constructor treats a violation as a programming error.
type CacheConfig struct {
	// TTL is the nominal freshness window. Past TTL a value is "stale": still
	// served (up to MaxStale) but logged as such.
	TTL time.Duration
	// RefreshAhead is the age at which a request triggers an asynchronous
	// refresh while still serving the cached value, so the hot path never
	// blocks on the vault and there is no cold window at TTL expiry.
	RefreshAhead time.Duration
	// MaxStale is the hard limit. A value older than MaxStale is not served:
	// the resolver falls back to a blocking resolve and fails closed on error.
	MaxStale time.Duration
	// ShouldCache decides per reference whether a value may be cached. It is
	// required: a nil predicate is rejected so a caller cannot accidentally
	// cache a value (such as a one-time password) that must never be reused.
	ShouldCache func(secretRef string) bool
	// Now defaults to time.Now when nil; tests inject a fixed clock.
	Now func() time.Time
	// Logger receives low-cardinality cache events; nil discards them. Event
	// fields carry the secret reference (a config URI) but never a value.
	Logger *slog.Logger
	// Jitter spreads a backoff duration to avoid synchronized retries; nil
	// uses a default [50%,100%) jitter. Tests inject the identity to assert
	// exact spacing.
	Jitter func(time.Duration) time.Duration
}

// CachedResolver wraps a broker.Resolver so credential resolution is a
// background concern: the inject path reads from an in-memory cache and the
// vault is queried at most once per reference per refresh interval. Concurrent
// misses are coalesced into one vault call (single-flight); an entry past its
// refresh-ahead age is refreshed asynchronously while its current value is
// served; and a transient vault failure keeps serving the last-known-good value
// up to MaxStale instead of failing closed. It is safe for concurrent use.
//
// Whether a given reference may be cached at all is delegated to the ShouldCache
// predicate (built from the credstore registry, so each vendor owns its own
// non-cacheable-ref rule); references the predicate rejects always hit the
// underlying resolver so their value stays current.
type CachedResolver struct {
	inner        broker.Resolver
	ttl          time.Duration
	refreshAhead time.Duration
	maxStale     time.Duration
	now          func() time.Time
	shouldCache  func(secretRef string) bool
	jitter       func(time.Duration) time.Duration
	logger       *slog.Logger

	sf singleflight.Group

	mu sync.Mutex
	// entries grows monotonically: an entry is created per resolved
	// (vaultID, secretRef) and never evicted. The key space is bounded by the
	// configured rules (a handful), so it cannot grow with request volume; a
	// ref removed from a hot-reloaded config lingers until restart.
	entries map[string]*entry
}

// entry is the per-reference cache state. value/fetchedAt are valid only when
// hasValue is set. failures/nextAttemptAt drive backoff; refreshing guards
// against spawning more than one background refresh goroutine per reference.
type entry struct {
	value         string
	hasValue      bool
	fetchedAt     time.Time
	lastErr       error
	failures      int
	nextAttemptAt time.Time
	refreshing    bool
}

// NewCachedResolver wraps inner with a background-refreshing cache. It returns
// an error if inner is nil, ShouldCache is nil, or the durations violate
// 0 < RefreshAhead < TTL <= MaxStale.
func NewCachedResolver(inner broker.Resolver, cfg CacheConfig) (*CachedResolver, error) {
	if inner == nil {
		return nil, errors.New("inner resolver is required")
	}
	if cfg.ShouldCache == nil {
		return nil, errors.New("shouldCache predicate is required")
	}
	if cfg.TTL <= 0 {
		return nil, errors.New("ttl must be positive")
	}
	if cfg.RefreshAhead <= 0 || cfg.RefreshAhead >= cfg.TTL {
		return nil, fmt.Errorf("refresh_ahead must satisfy 0 < refresh_ahead < ttl (got %s, ttl %s)", cfg.RefreshAhead, cfg.TTL)
	}
	if cfg.MaxStale < cfg.TTL {
		return nil, fmt.Errorf("max_stale must be >= ttl (got %s, ttl %s)", cfg.MaxStale, cfg.TTL)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	jitter := cfg.Jitter
	if jitter == nil {
		jitter = defaultJitter
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &CachedResolver{
		inner:        inner,
		ttl:          cfg.TTL,
		refreshAhead: cfg.RefreshAhead,
		maxStale:     cfg.MaxStale,
		now:          now,
		shouldCache:  cfg.ShouldCache,
		jitter:       jitter,
		logger:       logger,
		entries:      make(map[string]*entry),
	}, nil
}

// Resolve returns the credential for (vaultID, secretRef). A cacheable
// reference is served from memory whenever a usable value exists; the vault is
// touched only to populate a cold entry, to refresh ahead of expiry (off the
// request goroutine), or when a value has aged past MaxStale. References the
// ShouldCache predicate rejects always hit the underlying resolver.
func (c *CachedResolver) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	if !c.shouldCache(secretRef) {
		v, err := c.inner.Resolve(ctx, vaultID, secretRef)
		if err != nil {
			return "", fmt.Errorf("resolve %s: %w", secretRef, err)
		}
		return v, nil
	}

	k := cacheKey(vaultID, secretRef)
	now := c.now()

	c.mu.Lock()
	e := c.entries[k]
	if e != nil && e.hasValue {
		age := now.Sub(e.fetchedAt)
		if age < c.refreshAhead {
			value := e.value
			c.mu.Unlock()
			c.logger.Debug("broker cache hit", slog.String("secret_ref", secretRef))
			return value, nil
		}
		if age < c.maxStale {
			value := e.value
			lastErr := e.lastErr
			trigger := !e.refreshing && !now.Before(e.nextAttemptAt)
			if trigger {
				e.refreshing = true
			}
			stale := age >= c.ttl
			c.mu.Unlock()
			// Log and refresh only when we actually kick a refresh, so log
			// volume tracks refresh attempts (at most one per interval), not
			// request rate — a sustained outage would otherwise emit one Warn
			// per request for the whole serve-stale window.
			if trigger {
				c.spawnRefresh(ctx, k, vaultID, secretRef)
				if stale {
					c.logger.Warn("broker cache serving stale value",
						slog.String("secret_ref", secretRef),
						slog.Duration("age", age),
						slog.Any("last_refresh_err", lastErr),
					)
				} else {
					c.logger.Info("broker cache refresh ahead",
						slog.String("secret_ref", secretRef),
						slog.Duration("age", age),
					)
				}
			}
			return value, nil
		}
		// Past max_stale: fall through to a blocking resolve and fail closed
		// on error — the value is too old to serve.
	}

	// Not serveable (cold, or older than max_stale). Honor the backoff window
	// so a failing reference is not re-hammered on every request.
	if e != nil && now.Before(e.nextAttemptAt) {
		lastErr := e.lastErr
		c.mu.Unlock()
		c.logger.Warn("broker cache fail closed (backoff)", slog.String("secret_ref", secretRef))
		return "", fmt.Errorf("resolve %s: %w", secretRef, lastErr)
	}
	c.mu.Unlock()

	v, err := c.resolveSingleFlight(ctx, k, vaultID, secretRef)
	if err != nil {
		c.logger.Warn("broker cache fail closed", slog.String("secret_ref", secretRef))
		return "", fmt.Errorf("resolve %s: %w", secretRef, err)
	}
	return v, nil
}

// fetch resolves (vaultID, secretRef) from the underlying vault and updates the
// entry. An empty resolved value is treated as a failure (see
// errEmptyCredential). Success stores the value and resets backoff; failure
// records backoff and leaves any prior good value intact for serve-stale.
func (c *CachedResolver) fetch(ctx context.Context, k, vaultID, secretRef string) (string, error) {
	val, err := c.inner.Resolve(ctx, vaultID, secretRef)
	if err == nil && val == "" {
		err = errEmptyCredential
	}
	if err != nil {
		c.recordFailure(k, err)
		return "", err
	}
	c.store(k, val)
	return val, nil
}

// resolveSingleFlight performs a blocking vault resolve, collapsing concurrent
// callers for the same key into one call. Used for cold entries and values past
// MaxStale.
//
// The shared call is detached from the caller's context (bounded by
// refreshTimeout): the single-flight result is delivered to every concurrent
// cold caller, so if the call rode the first caller's request context, that
// caller disconnecting would cancel the vault call for all of them and — via
// fetch's recordFailure — poison the backoff window with a spurious "context
// canceled", failing healthy-vault requests closed. spawnRefresh detaches for
// the same reason.
func (c *CachedResolver) resolveSingleFlight(ctx context.Context, k, vaultID, secretRef string) (string, error) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()
	v, err, _ := c.sf.Do(k, func() (any, error) {
		return c.fetch(rctx, k, vaultID, secretRef)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// spawnRefresh refreshes k in the background, off the request goroutine. The
// context is detached from the request (which may complete first) and bounded
// by refreshTimeout. The single-flight group collapses this with any
// concurrent blocking resolve. The refreshing flag set by the caller is always
// cleared on completion, and a panic in the underlying resolver is recovered so
// a misbehaving vendor SDK on this detached goroutine cannot crash the proxy
// (the synchronous request path is already covered by the proxy handler's
// recover; this goroutine runs after the handler returns).
func (c *CachedResolver) spawnRefresh(reqCtx context.Context, k, vaultID, secretRef string) {
	go func() {
		defer c.clearRefreshing(k)
		defer func() {
			if r := recover(); r != nil {
				c.logger.Error("broker cache background refresh panicked",
					slog.String("secret_ref", secretRef),
					slog.Any("panic", r),
				)
			}
		}()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(reqCtx), refreshTimeout)
		defer cancel()

		_, err, _ := c.sf.Do(k, func() (any, error) {
			return c.fetch(ctx, k, vaultID, secretRef)
		})
		if err != nil {
			c.logger.Warn("broker cache background refresh failed (backoff)",
				slog.String("secret_ref", secretRef),
			)
			return
		}
		c.logger.Info("broker cache refreshed", slog.String("secret_ref", secretRef))
	}()
}

// store records a successful resolve: it sets the value, stamps fetchedAt, and
// clears any failure/backoff state.
func (c *CachedResolver) store(k, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[k]
	if e == nil {
		e = &entry{}
		c.entries[k] = e
	}
	e.value = value
	e.hasValue = true
	e.fetchedAt = c.now()
	e.failures = 0
	e.lastErr = nil
	e.nextAttemptAt = time.Time{}
}

// recordFailure advances the backoff schedule for k and remembers the error.
// It never clears an existing value, so a prior good credential stays
// serveable under serve-stale.
func (c *CachedResolver) recordFailure(k string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.entries[k]
	if e == nil {
		e = &entry{}
		c.entries[k] = e
	}
	e.failures++
	e.lastErr = err
	e.nextAttemptAt = c.now().Add(c.jitter(backoffFor(e.failures)))
}

func (c *CachedResolver) clearRefreshing(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[k]; e != nil {
		e.refreshing = false
	}
}

// backoffFor returns the un-jittered backoff for the nth consecutive failure:
// baseBackoff doubled per prior failure, capped at maxBackoff.
func backoffFor(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	d := baseBackoff
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return d
}

// defaultJitter returns a duration in [d/2, d) so retries for the same
// reference do not resynchronize after a shared outage.
func defaultJitter(d time.Duration) time.Duration {
	half := d / 2
	if half <= 0 {
		return d
	}
	// Backoff jitter spreads retry timing; it is not a security primitive, so a
	// weak RNG is appropriate.
	return half + rand.N(half) //nolint:gosec // G404: timing jitter, not security-sensitive
}

func cacheKey(vaultID, secretRef string) string {
	return vaultID + "\x00" + secretRef
}
