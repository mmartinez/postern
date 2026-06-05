package credstore_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/credstore"
)

// testClock is a thread-safe injectable clock. The cache refreshes off
// background goroutines that read the clock while the test advances it, so a
// plain mutable time.Time would data-race under -race.
type testClock struct{ ns atomic.Int64 }

func newTestClock(t time.Time) *testClock {
	c := &testClock{}
	c.ns.Store(t.UnixNano())
	return c
}

func (c *testClock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

var epoch = time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)

// fakeResolver lets a test pin the value (or error) returned for a given
// (vaultID, secretRef) pair and inspect how many times each combination was
// looked up. It satisfies broker.Resolver.
//
// Optional knobs exercise the background paths: block/entered gate a call so a
// test can observe an in-flight resolve off the request goroutine, and
// failConcurrent makes a second simultaneously in-flight call return a
// rate-limit error (the production thundering-herd condition).
type fakeResolver struct {
	mu     sync.Mutex
	values map[string]string
	errs   map[string]error
	calls  map[string]int
	total  atomic.Int64

	block   chan struct{} // non-nil: Resolve blocks until it is closed
	entered chan struct{} // non-nil: Resolve signals on entry, before blocking

	inflight       atomic.Int64
	failConcurrent bool
	panicAfter     int // >0: panic once a key's call count exceeds this
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{
		values: map[string]string{},
		errs:   map[string]error{},
		calls:  map[string]int{},
	}
}

func (f *fakeResolver) key(vaultID, ref string) string { return vaultID + "\x00" + ref }

func (f *fakeResolver) set(vaultID, ref, value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[f.key(vaultID, ref)] = value
}

func (f *fakeResolver) setErr(vaultID, ref string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[f.key(vaultID, ref)] = err
}

func (f *fakeResolver) clearErr(vaultID, ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.errs, f.key(vaultID, ref))
}

func (f *fakeResolver) setGate(block, entered chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = block
	f.entered = entered
}

func (f *fakeResolver) Resolve(ctx context.Context, vaultID, ref string) (string, error) {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)

	f.mu.Lock()
	k := f.key(vaultID, ref)
	f.calls[k]++
	callN := f.calls[k]
	f.total.Add(1)
	v := f.values[k]
	err := f.errs[k]
	block, entered, failConc := f.block, f.entered, f.failConcurrent
	panicAfter := f.panicAfter
	f.mu.Unlock()

	if entered != nil {
		// Non-blocking: signal that a call entered the vault without ever
		// blocking the caller. A blocking send would deadlock the code under
		// test if a scenario produced more in-flight calls than the test drains.
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		// Honor cancellation while blocked so a test can exercise a resolve
		// whose context is cancelled mid-call.
		select {
		case <-block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if panicAfter > 0 && callN > panicAfter {
		panic("fakeResolver: simulated resolver panic")
	}
	if failConc && n > 1 {
		return "", errors.New("rate limit exceeded")
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func (f *fakeResolver) callCount(vaultID, ref string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[f.key(vaultID, ref)]
}

// cacheEverything is the predicate most cache tests use: every reference is
// cacheable. The bypass behavior is exercised separately with a predicate
// that mirrors a vendor's non-cacheable-ref rule.
func cacheEverything(string) bool { return true }

// noJitter makes backoff deterministic so a test can assert exact spacing.
func noJitter(d time.Duration) time.Duration { return d }

// baseConfig returns a CacheConfig with the production-shaped defaults and the
// given clock. ttl 1h, refresh_ahead 45m, max_stale 24h; jitter disabled.
func baseConfig(clk *testClock) credstore.CacheConfig {
	return credstore.CacheConfig{
		TTL:          time.Hour,
		RefreshAhead: 45 * time.Minute,
		MaxStale:     24 * time.Hour,
		ShouldCache:  cacheEverything,
		Now:          clk.now,
		Jitter:       noJitter,
	}
}

func TestCachedResolver_ServesFreshWithinRefreshAhead(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "sk-abc")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		got, err := c.Resolve(context.Background(), "", "op://V/I/f")
		require.NoErrorf(t, err, "iter %d", i)
		require.Equalf(t, "sk-abc", got, "iter %d", i)
	}

	require.Equal(t, 1, inner.callCount("", "op://V/I/f"),
		"fresh reads within refresh_ahead must hit cache, not the vault")
}

// 50 concurrent requests on a cold ref must collapse into exactly one vault
// resolve. The fake blocks the first call in the vault; while that call is
// in-flight the single-flight key is held, so no second vault call can start —
// the collapse is asserted at that instant, which is deterministic regardless of
// how far each concurrent caller has progressed (no sleep, no straggler race).
func TestCachedResolver_SingleFlightCollapsesConcurrentColdResolves(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "sk-xyz")

	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	inner.setGate(block, entered)

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	const n = 50
	var wg sync.WaitGroup
	got := make([]string, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = c.Resolve(context.Background(), "", "op://V/I/f")
		}(i)
	}

	// The one in-flight vault call has begun and is blocked. While it holds the
	// single-flight key, no concurrent caller can start a second vault call, so
	// the collapse is provable now — before releasing the gate.
	<-entered
	require.Equal(t, int64(1), inner.total.Load(),
		"concurrent cold resolves must collapse into one in-flight vault call")

	close(block)
	wg.Wait()

	for i := 0; i < n; i++ {
		require.NoErrorf(t, errs[i], "caller %d", i)
		require.Equalf(t, "sk-xyz", got[i], "caller %d", i)
	}
}

// Prime the cache, then make the vault rate-limit. Requests must keep getting
// the last-known-good value (HTTP 200, zero 502s) up to max_stale, while a ref
// that was never resolved still fails closed.
func TestCachedResolver_ServesStaleOnRefreshError(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "good-token")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	// Prime.
	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "good-token", got)

	// Vault now rate-limits; advance into the stale-but-serveable window.
	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))
	clk.advance(time.Hour + time.Minute) // past ttl (1h), well under max_stale (24h)

	for i := 0; i < 5; i++ {
		got, err := c.Resolve(context.Background(), "", "op://V/I/f")
		require.NoErrorf(t, err, "iter %d: stale value must serve, not fail closed", i)
		require.Equalf(t, "good-token", got, "iter %d", i)
	}

	// A reference with no prior value must still fail closed.
	inner.setErr("", "op://V/I/never", errors.New("rate limit exceeded"))
	_, err = c.Resolve(context.Background(), "", "op://V/I/never")
	require.Error(t, err, "a never-resolved ref must fail closed even under serve-stale")
}

// Past max_stale the cached value is no longer serveable: a failing vault must
// fail closed, but a recovering vault repopulates and serves again.
func TestCachedResolver_FailsClosedBeyondMaxStale(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)

	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))
	clk.advance(25 * time.Hour) // past max_stale (24h)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err, "a value older than max_stale must not be served")
}

// A request whose entry has aged past refresh_ahead must return the cached
// value immediately (never block on the vault) and refresh asynchronously off
// the request goroutine.
func TestCachedResolver_BackgroundRefreshDoesNotBlockHotPath(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	// Prime.
	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "v1", got)

	// Age past refresh_ahead and make the next (background) resolve block.
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	inner.setGate(block, entered)
	inner.set("", "op://V/I/f", "v2")
	clk.advance(46 * time.Minute) // past refresh_ahead (45m), under ttl (1h)

	// The request must return the still-good v1 immediately even though the
	// background refresh is blocked in the vault. If it blocked, this would
	// deadlock against the unclosed gate.
	got, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "v1", got, "hot path must serve the cached value, not block on refresh")

	// The refresh runs on its own goroutine (it has entered the vault).
	<-entered
	close(block)

	require.Eventually(t, func() bool {
		v, err := c.Resolve(context.Background(), "", "op://V/I/f")
		return err == nil && v == "v2"
	}, 5*time.Second, time.Millisecond, "background refresh should eventually update the cache")

	require.Equal(t, 2, inner.callCount("", "op://V/I/f"),
		"exactly one prime + one background refresh")
}

// Repeated vault failures must be spaced by exponential backoff, not retried on
// every request.
func TestCachedResolver_BackoffSpacesRetries(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	// First attempt hits the vault and fails; backoff base is 1s.
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 1, inner.callCount("", "op://V/I/f"))

	// A second attempt within the backoff window must not call the vault.
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 1, inner.callCount("", "op://V/I/f"), "retry within backoff must not hit the vault")

	// After the backoff elapses, exactly one more attempt is allowed.
	clk.advance(time.Second)
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 2, inner.callCount("", "op://V/I/f"))

	// Backoff has doubled to 2s; an attempt 1s later is still gated.
	clk.advance(time.Second)
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 2, inner.callCount("", "op://V/I/f"), "backoff must grow, not stay flat")

	// 2s after the second failure, the next attempt is allowed.
	clk.advance(time.Second)
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 3, inner.callCount("", "op://V/I/f"))
}

// The production regression, deterministically: one secret_ref, a vault that is
// slow/rate-limited (its refresh is blocked in-flight), and sustained bursts of
// concurrent requests at the TTL boundary. Every request must serve the cached
// value (zero 502s) and the thundering herd must collapse to exactly one
// in-flight vault call. The gate makes this race-free — no polling.
func TestCachedResolver_RegressionNoStormUnderSustainedBursts(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "token")
	inner.failConcurrent = true // a second concurrent vault call would trip this

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	burst := func(round int) {
		var wg sync.WaitGroup
		var fails atomic.Int64
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := c.Resolve(context.Background(), "", "op://V/I/f"); err != nil {
					fails.Add(1)
				}
			}()
		}
		wg.Wait()
		require.Zerof(t, fails.Load(), "round %d: no request may fail closed", round)
	}

	// Prime with a single resolve (deterministic); the concurrent cold-collapse
	// is covered by the single-flight test.
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, int64(1), inner.total.Load())

	// Cross the refresh-ahead boundary and block the (single) background refresh
	// in the vault to simulate a slow / rate-limited vault.
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	inner.setGate(block, entered)
	clk.advance(46 * time.Minute)

	// Sustained bursts at the boundary while that one refresh is stuck: 50
	// requests, all serve the cached value, none triggers a second vault call.
	for round := 0; round < 5; round++ {
		burst(round)
	}
	<-entered // exactly one refresh reached the vault across every burst

	require.Equal(t, int64(2), inner.total.Load(),
		"the herd collapsed to one prime + one refresh; sustained bursts added no vault calls")
	close(block)
}

// The cache is vendor-agnostic: it sits in front of every provider, so a bw://
// reference gets the same serve-stale protection as an op:// ref. This guards
// the same regression for every scheme, not only op.
func TestCachedResolver_VendorAgnosticServeStale(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "bw://0123abcd", "bw-secret")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "bw://0123abcd")
	require.NoError(t, err)

	inner.setErr("", "bw://0123abcd", errors.New("rate limit exceeded"))
	clk.advance(2 * time.Hour) // past ttl, under max_stale

	got, err := c.Resolve(context.Background(), "", "bw://0123abcd")
	require.NoError(t, err, "bw:// refs must serve stale on vault error, same as op:// refs")
	require.Equal(t, "bw-secret", got)
}

// An empty resolved value ("", nil) is never a usable credential, so the cache
// must treat it as a failure: fail closed and not cache it (so a deleted secret
// is not served as a "fresh" blank and is re-resolved on recovery).
func TestCachedResolver_EmptyResolvedValueFailsClosed(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "") // resolves successfully to an empty value

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err, "an empty credential must fail closed, not be served")
	require.Equal(t, 1, inner.callCount("", "op://V/I/f"))

	// Not cached as a success: after the backoff window it is re-resolved.
	clk.advance(2 * time.Second)
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 2, inner.callCount("", "op://V/I/f"), "empty value must not be cached")
}

// A successful resolve resets the backoff schedule: a later failure backs off
// from the base again, not from the grown pre-success interval.
func TestCachedResolver_BackoffResetsAfterSuccess(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	// Two failures grow the backoff to 2s.
	_, _ = c.Resolve(context.Background(), "", "op://V/I/f") // call 1, backoff 1s
	clk.advance(time.Second)
	_, _ = c.Resolve(context.Background(), "", "op://V/I/f") // call 2, backoff 2s
	require.Equal(t, 2, inner.callCount("", "op://V/I/f"))

	// Recover: the next attempt (after the 2s backoff) succeeds and resets state.
	clk.advance(2 * time.Second)
	inner.clearErr("", "op://V/I/f")
	inner.set("", "op://V/I/f", "v")
	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "v", got)
	require.Equal(t, 3, inner.callCount("", "op://V/I/f"))

	// Fail again past max_stale (value unservable → blocking resolve). If backoff
	// had NOT reset, it would now be 4s; a 1s advance proves it is back to base.
	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))
	clk.advance(25 * time.Hour)
	_, err = c.Resolve(context.Background(), "", "op://V/I/f") // call 4, backoff 1s if reset
	require.Error(t, err)
	require.Equal(t, 4, inner.callCount("", "op://V/I/f"))

	clk.advance(time.Second) // exactly base backoff later
	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err)
	require.Equal(t, 5, inner.callCount("", "op://V/I/f"),
		"backoff must reset to base after a success, not stay grown")
}

// At exactly refresh_ahead age the value is still served, and a background
// refresh is triggered (the boundary uses a strict `age < refresh_ahead`).
func TestCachedResolver_RefreshAheadBoundaryTriggersRefresh(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)

	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	inner.setGate(block, entered)
	clk.advance(45 * time.Minute) // exactly refresh_ahead

	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "v1", got, "value served at the refresh_ahead boundary")
	<-entered // a refresh was triggered at exactly refresh_ahead
	close(block)
}

// At exactly max_stale age the value is no longer serveable (strict
// `age < max_stale`): a failing vault must fail closed, not serve the value.
func TestCachedResolver_MaxStaleBoundaryFailsClosed(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)

	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))
	clk.advance(24 * time.Hour) // exactly max_stale

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.Error(t, err, "a value exactly at max_stale age must not be served")
}

// A non-cacheable (bypass) reference whose resolve errors must fail closed and
// name the secret_ref, and must not be cached.
func TestCachedResolver_NonCacheableRefErrorFailsClosed(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.setErr("", "op://V/I/totp?attribute=otp", errors.New("backend boom"))

	cfg := baseConfig(clk)
	cfg.ShouldCache = func(ref string) bool { return !strings.HasSuffix(ref, "?attribute=otp") }

	c, err := credstore.NewCachedResolver(inner, cfg)
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/totp?attribute=otp")
	require.Error(t, err)
	require.Contains(t, err.Error(), "op://V/I/totp?attribute=otp")

	// Bypass path is not cached or backoff-gated: it hits the vault every time.
	_, err = c.Resolve(context.Background(), "", "op://V/I/totp?attribute=otp")
	require.Error(t, err)
	require.Equal(t, 2, inner.callCount("", "op://V/I/totp?attribute=otp"))
}

// After a failed background refresh the refreshing flag must be cleared so the
// next interval can refresh again (a stuck flag would wedge the ref into
// serving stale forever).
func TestCachedResolver_RefreshingFlagClearedAfterFailedRefresh(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)

	inner.setErr("", "op://V/I/f", errors.New("rate limit exceeded"))
	clk.advance(46 * time.Minute) // past refresh_ahead

	// First request triggers a background refresh that fails.
	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "v1", got)
	require.Eventually(t, func() bool {
		return inner.callCount("", "op://V/I/f") == 2
	}, 5*time.Second, time.Millisecond, "first background refresh should run")

	// Past the backoff window, a later request must trigger a second refresh —
	// proving the refreshing flag was released after the first failure. Issue the
	// request inside the poll: callCount reaches 2 when the first refresh enters
	// the vault, which is before it clears the refreshing flag, so a single
	// request here could land while the flag is still set. Retrying drives the
	// trigger once the flag is cleared (and fails the test if it never clears).
	clk.advance(2 * time.Second)
	require.Eventually(t, func() bool {
		got, err := c.Resolve(context.Background(), "", "op://V/I/f")
		return err == nil && got == "v1" && inner.callCount("", "op://V/I/f") >= 3
	}, 5*time.Second, time.Millisecond, "refreshing flag must be cleared so the next interval refreshes")
}

// A panic in the underlying resolver on the detached background-refresh
// goroutine must be recovered, not crash the process. (If it were not
// recovered, the unrecovered goroutine panic would abort the test binary.)
func TestCachedResolver_BackgroundRefreshSurvivesResolverPanic(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")
	inner.panicAfter = 1 // first (priming) call ok; the refresh panics

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)

	clk.advance(46 * time.Minute) // past refresh_ahead
	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "v1", got, "hot path still serves the cached value")

	// The background refresh ran (and panicked, and was recovered). If the panic
	// escaped, this test process would have crashed before reaching here.
	require.Eventually(t, func() bool {
		return inner.callCount("", "op://V/I/f") == 2
	}, 5*time.Second, time.Millisecond, "background refresh should have run and been recovered")
}

// A cold resolve is single-flighted across all concurrent callers using one
// shared vault call. If that call rode the first caller's request context, that
// caller disconnecting would cancel the vault call for everyone and poison the
// backoff window with a spurious "context canceled", failing healthy-vault
// requests closed. The shared resolve must be detached from any one caller.
func TestCachedResolver_CancelledColdResolveDoesNotPoisonBackoff(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	inner.setGate(block, entered)

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	// Cold resolve whose caller cancels mid-flight.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = c.Resolve(ctx, "", "op://V/I/f")
	}()
	<-entered // the vault call is in flight
	cancel()  // caller disconnects
	close(block)
	<-done

	// A subsequent request must get the cached value, not a poisoned backoff.
	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err, "a cancelled cold resolve must not poison backoff for healthy requests")
	require.Equal(t, "v1", got)
}

func TestCachedResolver_NonCacheableRefBypassesCache(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("", "op://V/I/totp?attribute=otp", "123456")

	cfg := baseConfig(clk)
	// Mirror a vendor that marks OTP references non-cacheable.
	cfg.ShouldCache = func(ref string) bool { return !strings.HasSuffix(ref, "?attribute=otp") }

	c, err := credstore.NewCachedResolver(inner, cfg)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := c.Resolve(context.Background(), "", "op://V/I/totp?attribute=otp")
		require.NoErrorf(t, err, "iter %d", i)
	}

	require.Equal(t, 3, inner.callCount("", "op://V/I/totp?attribute=otp"),
		"non-cacheable refs must bypass the cache on every request")
}

// The wrapped resolve error must name the secret reference (a URI like
// op://Vault/Item/field, not the credential value) so an operator can tell
// which rule failed.
func TestCachedResolver_ColdErrorNamesSecretRef(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.setErr("", "op://Vault/Item/field", errors.New("backend boom"))

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	_, err = c.Resolve(context.Background(), "", "op://Vault/Item/field")
	require.Error(t, err)
	require.Contains(t, err.Error(), "op://Vault/Item/field", "error should name the secret_ref")
}

func TestCachedResolver_VaultIDsCacheSeparately(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	inner.set("vault-a", "op://V/I/f", "a-value")
	inner.set("vault-b", "op://V/I/f", "b-value")

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	gotA, err := c.Resolve(context.Background(), "vault-a", "op://V/I/f")
	require.NoError(t, err)
	gotB, err := c.Resolve(context.Background(), "vault-b", "op://V/I/f")
	require.NoError(t, err)

	require.Equal(t, "a-value", gotA)
	require.Equal(t, "b-value", gotB)
}

// CachedResolver documents itself safe for concurrent use; the broker hot path
// calls Resolve concurrently across requests. Hammer it from many goroutines
// over several keys and assert values stay consistent. Run with -race.
func TestCachedResolver_ConcurrentResolveIsRaceFree(t *testing.T) {
	t.Parallel()

	clk := newTestClock(epoch)
	inner := newFakeResolver()
	const keys = 8
	for i := 0; i < keys; i++ {
		inner.set("", "op://V/I/"+strconv.Itoa(i), "val-"+strconv.Itoa(i))
	}

	c, err := credstore.NewCachedResolver(inner, baseConfig(clk))
	require.NoError(t, err)

	const goroutines = 16
	const iterations = 200
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				k := (g + i) % keys
				ref := "op://V/I/" + strconv.Itoa(k)
				got, err := c.Resolve(context.Background(), "", ref)
				if err != nil {
					t.Errorf("Resolve(%s): %v", ref, err)
					return
				}
				if want := "val-" + strconv.Itoa(k); got != want {
					t.Errorf("ref %s = %q, want %q", ref, got, want)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

func TestNewCachedResolver_RejectsBadConfig(t *testing.T) {
	t.Parallel()

	inner := newFakeResolver()
	okCfg := func() credstore.CacheConfig {
		return credstore.CacheConfig{
			TTL:          time.Hour,
			RefreshAhead: 45 * time.Minute,
			MaxStale:     24 * time.Hour,
			ShouldCache:  cacheEverything,
		}
	}

	// nil inner is rejected.
	_, err := credstore.NewCachedResolver(nil, okCfg())
	require.Error(t, err, "nil inner resolver")

	tests := []struct {
		name string
		mut  func(c *credstore.CacheConfig)
	}{
		{"zero ttl", func(c *credstore.CacheConfig) { c.TTL = 0 }},
		{"refresh_ahead not positive", func(c *credstore.CacheConfig) { c.RefreshAhead = 0 }},
		{"refresh_ahead >= ttl", func(c *credstore.CacheConfig) { c.RefreshAhead = c.TTL }},
		{"max_stale < ttl", func(c *credstore.CacheConfig) { c.MaxStale = c.TTL - time.Second }},
		{"nil shouldCache", func(c *credstore.CacheConfig) { c.ShouldCache = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := okCfg()
			tc.mut(&cfg)
			_, err := credstore.NewCachedResolver(inner, cfg)
			require.Error(t, err)
		})
	}
}
