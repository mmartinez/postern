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

	"github.com/mmartinez/postern/internal/credstore"
)

// fakeResolver lets a test pin the value (or error) returned for a given
// (vaultID, secretRef) pair and inspect how many times each combination was
// looked up. It satisfies broker.Resolver.
type fakeResolver struct {
	mu     sync.Mutex
	values map[string]string
	errs   map[string]error
	calls  map[string]int
	total  atomic.Int64
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

func (f *fakeResolver) Resolve(_ context.Context, vaultID, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := f.key(vaultID, ref)
	f.calls[k]++
	f.total.Add(1)
	if err, ok := f.errs[k]; ok {
		return "", err
	}
	return f.values[k], nil
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

func TestCachedResolver_CachesWithinTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "sk-abc")

	c, err := credstore.NewCachedResolver(inner, 10, time.Minute, clock, cacheEverything)
	if err != nil {
		t.Fatalf("NewCachedResolver: %v", err)
	}

	for i := 0; i < 5; i++ {
		got, err := c.Resolve(context.Background(), "", "op://V/I/f")
		if err != nil {
			t.Fatalf("iter %d: Resolve: %v", i, err)
		}
		if got != "sk-abc" {
			t.Fatalf("iter %d: got %q, want %q", i, got, "sk-abc")
		}
	}

	if calls := inner.callCount("", "op://V/I/f"); calls != 1 {
		t.Fatalf("inner.Resolve called %d times, want 1 (cache hit on retries)", calls)
	}
}

func TestCachedResolver_ExpiresAfterTTL(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	inner := newFakeResolver()
	inner.set("", "op://V/I/f", "v1")

	c, _ := credstore.NewCachedResolver(inner, 10, time.Minute, clock, cacheEverything)

	_, _ = c.Resolve(context.Background(), "", "op://V/I/f")

	// Just past the TTL window — entry expires.
	now = now.Add(time.Minute + time.Nanosecond)
	inner.set("", "op://V/I/f", "v2")

	got, err := c.Resolve(context.Background(), "", "op://V/I/f")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "v2" {
		t.Fatalf("got %q, want %q (expected re-resolve after TTL)", got, "v2")
	}
	if calls := inner.callCount("", "op://V/I/f"); calls != 2 {
		t.Fatalf("inner.Resolve called %d times, want 2", calls)
	}
}

func TestCachedResolver_NonCacheableRefBypassesCache(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	inner := newFakeResolver()
	inner.set("", "op://V/I/totp?attribute=otp", "123456")

	// Mirror a vendor that marks OTP references non-cacheable.
	bypassOTP := func(ref string) bool { return !strings.HasSuffix(ref, "?attribute=otp") }

	c, _ := credstore.NewCachedResolver(inner, 10, time.Hour, clock, bypassOTP)

	for i := 0; i < 3; i++ {
		if _, err := c.Resolve(context.Background(), "", "op://V/I/totp?attribute=otp"); err != nil {
			t.Fatalf("iter %d: Resolve: %v", i, err)
		}
	}

	if calls := inner.callCount("", "op://V/I/totp?attribute=otp"); calls != 3 {
		t.Fatalf("non-cacheable inner.Resolve calls = %d, want 3 (bypass cache)", calls)
	}
}

func TestCachedResolver_ErrorsArePropagatedAndNotCached(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	sentinel := errors.New("token revoked")
	inner := newFakeResolver()
	inner.setErr("", "op://V/I/f", sentinel)

	c, _ := credstore.NewCachedResolver(inner, 10, time.Minute, clock, cacheEverything)

	for i := 0; i < 3; i++ {
		_, err := c.Resolve(context.Background(), "", "op://V/I/f")
		if !errors.Is(err, sentinel) {
			t.Fatalf("iter %d: got err %v, want wrap of %v", i, err, sentinel)
		}
	}
	if calls := inner.callCount("", "op://V/I/f"); calls != 3 {
		t.Fatalf("inner.Resolve calls = %d, want 3 (errors not cached)", calls)
	}
}

// The wrapped resolve error must name the secret reference (a URI like
// op://Vault/Item/field — not the credential value), so an operator can tell
// which rule failed. It previously interpolated the always-empty vaultID.
func TestCachedResolver_ErrorNamesTheSecretRef(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	inner := newFakeResolver()
	inner.setErr("", "op://Vault/Item/field", errors.New("backend boom"))

	c, _ := credstore.NewCachedResolver(inner, 10, time.Minute, func() time.Time { return now }, cacheEverything)

	_, err := c.Resolve(context.Background(), "", "op://Vault/Item/field")
	if err == nil || !strings.Contains(err.Error(), "op://Vault/Item/field") {
		t.Fatalf("error should name the secret_ref, got: %v", err)
	}
}

// CachedResolver documents itself safe for concurrent use; the broker hot path
// calls Resolve concurrently across requests. Hammer it from many goroutines
// over a key space larger than the capacity (forcing concurrent eviction) and
// assert values stay consistent. Run with -race to catch data races in the
// mutex-guarded LRU and the unlock-before-inner.Resolve re-check.
func TestCachedResolver_ConcurrentResolveIsRaceFree(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	inner := newFakeResolver()
	const keys = 8
	for i := 0; i < keys; i++ {
		inner.set("", "op://V/I/"+strconv.Itoa(i), "val-"+strconv.Itoa(i))
	}
	// Capacity smaller than the key space forces concurrent eviction.
	c, _ := credstore.NewCachedResolver(inner, 4, time.Hour, func() time.Time { return now }, cacheEverything)

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

func TestCachedResolver_LRUEvictsOldestWhenAtCapacity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	inner := newFakeResolver()
	for i := 0; i < 4; i++ {
		inner.set("", "op://V/I/"+strconv.Itoa(i), "v"+strconv.Itoa(i))
	}

	c, _ := credstore.NewCachedResolver(inner, 2, time.Hour, clock, cacheEverything)

	_, _ = c.Resolve(context.Background(), "", "op://V/I/0") // miss → loads 0
	_, _ = c.Resolve(context.Background(), "", "op://V/I/1") // miss → loads 1 (cache: 0, 1)
	_, _ = c.Resolve(context.Background(), "", "op://V/I/2") // miss → loads 2, evicts 0 (cache: 1, 2)

	// 0 should be re-resolved (was evicted).
	_, _ = c.Resolve(context.Background(), "", "op://V/I/0")
	// 2 should still be cached.
	_, _ = c.Resolve(context.Background(), "", "op://V/I/2")

	if got := inner.callCount("", "op://V/I/0"); got != 2 {
		t.Fatalf("inner.Resolve(op://V/I/0) = %d, want 2 (re-resolved after eviction)", got)
	}
	if got := inner.callCount("", "op://V/I/2"); got != 1 {
		t.Fatalf("inner.Resolve(op://V/I/2) = %d, want 1 (cache hit)", got)
	}
}

func TestCachedResolver_VaultIDsCacheSeparately(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 28, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	inner := newFakeResolver()
	inner.set("vault-a", "op://V/I/f", "a-value")
	inner.set("vault-b", "op://V/I/f", "b-value")

	c, _ := credstore.NewCachedResolver(inner, 10, time.Hour, clock, cacheEverything)

	gotA, _ := c.Resolve(context.Background(), "vault-a", "op://V/I/f")
	gotB, _ := c.Resolve(context.Background(), "vault-b", "op://V/I/f")

	if gotA != "a-value" || gotB != "b-value" {
		t.Fatalf("per-vault values: got (%q,%q), want (%q,%q)", gotA, gotB, "a-value", "b-value")
	}
}

func TestNewCachedResolver_RejectsBadConfig(t *testing.T) {
	t.Parallel()

	inner := newFakeResolver()

	if _, err := credstore.NewCachedResolver(nil, 1, time.Second, time.Now, cacheEverything); err == nil {
		t.Fatal("NewCachedResolver(nil inner): want error")
	}
	if _, err := credstore.NewCachedResolver(inner, 0, time.Second, time.Now, cacheEverything); err == nil {
		t.Fatal("NewCachedResolver(capacity=0): want error")
	}
	if _, err := credstore.NewCachedResolver(inner, 1, 0, time.Now, cacheEverything); err == nil {
		t.Fatal("NewCachedResolver(ttl=0): want error")
	}
	if _, err := credstore.NewCachedResolver(inner, 1, time.Second, time.Now, nil); err == nil {
		t.Fatal("NewCachedResolver(nil shouldCache): want error")
	}
}
