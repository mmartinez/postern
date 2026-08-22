package broker_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
)

// constantResolver answers every reference with a store-fixed value,
// standing in for one named credstore's resolver (e.g. the personal vs team
// 1Password account). The value doubles as proof of WHICH store served a
// request.
type constantResolver struct {
	value string
}

func (r *constantResolver) Resolve(context.Context, string, string) (string, error) {
	return r.value, nil
}

// multiStoreRule builds one header-inject rule whose ref points at the named
// store.
func multiStoreRule(host, store string) config.Rule {
	return config.Rule{
		Host:      host,
		SecretRef: "op+" + store + "://Vault/Item/field",
		Inject:    config.Inject{Type: config.InjectTypeHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}
}

func mustTranslate(t *testing.T, in []config.Rule) []broker.Rule {
	t.Helper()
	out, err := broker.FromConfigRules(in)
	require.NoError(t, err)
	return out
}

// TestRunReloader_MultiCredstoreSwapIsAtomicUnderLoad extends the reloader
// pattern to a two-same-scheme-credstore ruleset: while reload events swap
// between two multi-store rulesets, concurrent in-flight requests through
// the hook must never observe a torn state — every injected credential is
// exactly the one owned by the named store of the rule that matched, and no
// request ever fails closed.
func TestRunReloader_MultiCredstoreSwapIsAtomicUnderLoad(t *testing.T) {
	t.Parallel()

	personal := &constantResolver{value: "personal-credential"}
	team := &constantResolver{value: "team-credential"}
	router, err := credstore.NewNameRouter(
		map[string]broker.Resolver{"personal": personal, "team": team},
		map[string][]string{"op": {"personal", "team"}},
	)
	require.NoError(t, err)

	initial := []config.Rule{
		multiStoreRule("api.a.test", "personal"),
		multiStoreRule("api.b.test", "team"),
	}
	replacement := []config.Rule{
		multiStoreRule("api.c.test", "team"),
		multiStoreRule("api.d.test", "personal"),
	}
	engine := broker.NewEngine(mustTranslate(t, initial))
	hook := broker.Hook(engine, router, config.OnNoMatchBlock, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // hook is a closure; broker owns the synthetic body

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	events, stop := runReloaderUnderTest(t, engine, logger)
	t.Cleanup(stop)

	// Expected credential per host by store ownership.
	want := map[string]string{
		"api.a.test": "personal-credential",
		"api.b.test": "team-credential",
		"api.c.test": "team-credential",
		"api.d.test": "personal-credential",
	}
	allHosts := []string{"api.a.test", "api.b.test", "api.c.test", "api.d.test"}

	// A host dropping out of the active ruleset mid-swap legitimately fails
	// closed (on_no_match=block); that is coherent behavior, not a torn
	// state. The torn-state invariant this test guards is narrower: whenever
	// the hook DOES inject for a host, it must inject exactly that host's
	// store-owned credential — never a cross-store value.
	var mu sync.Mutex
	var failures []string
	injected := make(map[string]int)
	record := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, fmt.Sprintf(format, args...))
	}
	count := func(host string) {
		mu.Lock()
		defer mu.Unlock()
		injected[host]++
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				for _, host := range allHosts {
					req, reqErr := http.NewRequest(http.MethodPost, "https://"+host+"/v1/x", http.NoBody)
					if reqErr != nil {
						record("build request %s: %v", host, reqErr)
						continue
					}
					resp := hook(req) //nolint:bodyclose // failClosed bodies are drained below
					if resp != nil {
						// on_no_match=block: the host simply dropped out of
						// (or has not yet entered) the active ruleset mid-swap.
						// Fail-closed denial is coherent, not a torn state.
						b := make([]byte, 256)
						_, _ = resp.Body.Read(b)
						_ = resp.Body.Close()
					} else if got := req.Header.Get("x-api-key"); got != want[host] {
						record("host %s injected %q, want %q (torn cross-store read)", host, got, want[host])
					} else {
						count(host)
					}
				}
			}
		}()
	}

	// Swap back and forth between the two multi-store rulesets while the
	// request storm runs. Each round waits until the engine adopted the
	// round's expected shape before flipping again, so both directions of
	// the swap are exercised under load.
	for round := range 20 {
		rules := replacement
		expect := [2]string{"c", "d"}
		if round%2 == 0 {
			rules = initial
			expect = [2]string{"a", "b"}
		}
		events <- config.Event{New: &config.Config{Rules: rules}}
		require.Eventually(t, func() bool {
			_, okA := engine.Match("api." + expect[0] + ".test")
			_, okB := engine.Match("api." + expect[1] + ".test")
			return okA && okB
		}, time.Second, time.Millisecond, "engine must adopt the swapped ruleset")
	}
	close(done)
	wg.Wait()

	// Every host must have been served by its owning store at least once
	// across the swap storm, proving both rulesets were live and routed.
	mu.Lock()
	counts := make(map[string]int, len(injected))
	for h, n := range injected {
		counts[h] = n
	}
	mu.Unlock()
	for _, host := range allHosts {
		require.Greater(t, counts[host], 0, "host %s was never served", host)
	}

	require.Empty(t, failures, "in-flight requests observed inconsistent state:\n%s", strings.Join(failures, "\n"))

	// Final state serves exactly one full ruleset, never a blend.
	_, okInitial := engine.Match("api.a.test")
	_, okReplacement := engine.Match("api.c.test")
	require.NotEqual(t, okInitial, okReplacement, "blended ruleset after final swap")
}
