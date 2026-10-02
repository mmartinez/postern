package broker_test

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

// runReloaderWithVersion is runReloaderUnderTest plus a version counter:
// it starts the reloader wired to a fresh counter and returns the events
// channel, the counter, and a cancel that joins the goroutine.
func runReloaderWithVersion(t *testing.T, engine *broker.Engine) (chan<- config.Event, *broker.VersionCounter, context.CancelFunc) {
	t.Helper()
	return runReloaderWired(t, engine, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// runReloaderWired adds the two knobs the policy-aware guard needs: the
// startup baseline (which carries the bound on_no_match) and a logger the
// test can read back to prove the reloader actually consumed an event.
func runReloaderWired(
	t *testing.T,
	engine *broker.Engine,
	baseline *broker.Baseline,
	logger *slog.Logger,
) (chan<- config.Event, *broker.VersionCounter, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 4)
	counter := broker.NewVersionCounter()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, logger, baseline, counter)
	}()

	return events, counter, func() {
		cancel()
		close(events)
		wg.Wait()
	}
}

// TestVersionCounter_IncrementsPerHotReload covers the acceptance criterion
// "the loaded ruleset version (incremented per hot reload)": construction
// seeds the boot ruleset at version 1, every applied swap bumps the
// counter, and a rejected (fatal-lint) reload leaves it untouched.
func TestVersionCounter_IncrementsPerHotReload(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	events, counter, stop := runReloaderWithVersion(t, engine)
	t.Cleanup(stop)

	require.Equal(t, uint64(1), counter.Load(), "boot ruleset must seed version 1")

	// A clean reload bumps the version.
	events <- config.Event{
		New: &config.Config{
			Rules: []config.Rule{{
				Host:      "api.second.test",
				SecretRef: "op://Vault/Item/field",
				Inject: config.Inject{
					Type:     config.InjectTypeHeader,
					Name:     "x-api-key",
					Template: "{{ CREDENTIAL }}",
				},
			}},
		},
	}
	require.Eventually(t, func() bool {
		return counter.Load() == 2
	}, 2*time.Second, 10*time.Millisecond, "applied swap must bump version to 2")

	// A rejected reload (fatal lint) must not count as a version.
	events <- config.Event{
		Lints: []config.LintError{{Message: "broken", Severity: config.SeverityError}},
	}
	require.Never(t, func() bool {
		return counter.Load() != 2
	}, 300*time.Millisecond, 20*time.Millisecond, "rejected reloads must not bump the version")
}

// TestVersionCounter_EmptyRulesetRejectionDoesNotBump pins the same invariant
// for the empty-ruleset guard: the swap is refused and the version stays put,
// so GET /healthz never reports a config change that did not land. The event
// carries the non-fatal lint the validator now emits for this shape, so the
// rejected reload looks exactly like a real one.
func TestVersionCounter_EmptyRulesetRejectionDoesNotBump(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine([]broker.Rule{{
		Host:      "api.first.test",
		SecretRef: "op://Vault/Item/field",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}})
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	events, counter, stop := runReloaderWired(t, engine, nil, logger)
	t.Cleanup(stop)

	require.Equal(t, uint64(1), counter.Load(), "boot ruleset must seed version 1")

	events <- config.Event{
		New: &config.Config{Proxy: config.Proxy{Listen: "127.0.0.1:1701"}},
		Lints: []config.LintError{{
			Path:     "rules",
			Message:  "no rules with a credential source configured",
			Severity: config.SeverityWarning,
		}},
	}

	// Assert the reloader consumed the event before asserting what it did:
	// a counter that never moved would also pass if the event was never read.
	require.Eventually(t, func() bool {
		return strings.Contains(logBuf.String(), "ruleset keeps serving")
	}, 2*time.Second, 10*time.Millisecond, "reloader must log the rejection")

	require.Never(t, func() bool {
		return counter.Load() != 1
	}, 300*time.Millisecond, 20*time.Millisecond, "a refused empty ruleset must not bump the version")

	if _, ok := engine.Match("api.first.test"); !ok {
		t.Error("the previous ruleset must keep serving after the refusal")
	}
}

// TestVersionCounter_LoadIsConcurrencySafe exercises concurrent Load while
// swaps bump the counter — the admin endpoint scrapes from an HTTP handler
// goroutine while the reloader goroutine mutates.
func TestVersionCounter_LoadIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	counter := broker.NewVersionCounter()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			counter.Bump()
		}
	}()
	for i := 0; i < 1000; i++ {
		if v := counter.Load(); v > 1001 {
			t.Fatalf("impossible version %d observed", v)
		}
	}
	<-done
	require.Equal(t, uint64(1001), counter.Load())
}

// TestRunReloader_NilVersionCounter tolerates the legacy call shape: the
// variadic counter is optional so existing callers keep compiling and
// behave identically.
func TestRunReloader_NilVersionCounter(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, nil, nil)
	}()

	events <- config.Event{New: &config.Config{Rules: []config.Rule{{ //nolint:goconst // test fixture
		Host:      "api.legacy.test",
		SecretRef: "op://Vault/Item/field",
		Inject: config.Inject{
			Type:     config.InjectTypeHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}}}}

	require.Eventually(t, func() bool {
		_, ok := engine.Match("api.legacy.test")
		return ok
	}, 2*time.Second, 10*time.Millisecond)

	cancel()
	close(events)
	wg.Wait()
}
