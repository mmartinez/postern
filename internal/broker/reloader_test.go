package broker_test

import (
	"bytes"
	"context"
	"encoding/json"
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

// runReloaderUnderTest starts the reloader in a goroutine and returns the
// events channel + a cancel that also waits for the goroutine to exit. The
// helper keeps each test free of the same boilerplate.
func runReloaderUnderTest(t *testing.T, engine *broker.Engine, logger *slog.Logger) (chan<- config.Event, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 4)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, logger, nil)
	}()

	return events, func() {
		cancel()
		close(events)
		wg.Wait()
	}
}

func TestRunReloader_SwapsEngineOnValidEvent(t *testing.T) {
	t.Parallel()

	initial := []broker.Rule{{
		Host:      "api.first.test",
		SecretRef: "op://Vault/Item/field",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}}
	engine := broker.NewEngine(initial)

	events, stop := runReloaderUnderTest(t, engine, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(stop)

	// Initial state: first.test matches; second.test does not.
	if _, ok := engine.Match("api.first.test"); !ok {
		t.Fatal("baseline rule should match before reload")
	}
	if _, ok := engine.Match("api.second.test"); ok {
		t.Fatal("second.test must not match before reload")
	}

	// Push a valid reload that replaces the ruleset.
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
		_, ok := engine.Match("api.second.test")
		return ok
	}, 2*time.Second, 10*time.Millisecond, "engine must adopt new rule")
	if _, ok := engine.Match("api.first.test"); ok {
		t.Error("old rule should be gone after swap")
	}
}

func TestRunReloader_KeepsRulesOnInvalidEvent(t *testing.T) {
	t.Parallel()

	initial := []broker.Rule{{
		Host:      "api.first.test",
		SecretRef: "op://Vault/Item/field",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}}
	engine := broker.NewEngine(initial)

	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	events, stop := runReloaderUnderTest(t, engine, logger)
	t.Cleanup(stop)

	// Event with a fatal lint must not swap the engine.
	events <- config.Event{
		New: &config.Config{
			Rules: []config.Rule{{
				Host:      "api.broken.test",
				SecretRef: "op://Vault/Item/field",
				Inject: config.Inject{
					Type:     config.InjectTypeHeader,
					Name:     "x-api-key",
					Template: "{{ CREDENTIAL }}",
				},
			}},
		},
		Lints: []config.LintError{{
			Severity: config.SeverityError,
			Path:     "rules[0].secret_ref",
			Message:  "fake fatal lint for the test",
		}},
	}

	// Give the reloader time to process and log.
	require.Eventually(t, func() bool {
		return strings.Contains(logBuf.String(), "config reload rejected")
	}, 2*time.Second, 10*time.Millisecond, "reloader must log the rejection")

	// Engine still serves the original ruleset.
	if _, ok := engine.Match("api.first.test"); !ok {
		t.Error("original rule must still match after rejected reload")
	}
	if _, ok := engine.Match("api.broken.test"); ok {
		t.Error("rejected rule must not be applied")
	}

	// Log line carries the lint payload so operators can debug.
	var lastLine map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(logBuf.bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		_ = json.Unmarshal(line, &lastLine)
	}
	require.NotNil(t, lastLine)
	require.Equal(t, "WARN", lastLine["level"])
}

// syncBuffer is a goroutine-safe bytes.Buffer used by tests that read log
// output from the main goroutine while the reloader goroutine writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

func TestRunReloader_PassesWarningsThrough(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	events, stop := runReloaderUnderTest(t, engine, logger)
	t.Cleanup(stop)

	// A warning (e.g. missing CREDENTIAL placeholder) is non-fatal and must
	// not block the swap.
	events <- config.Event{
		New: &config.Config{
			Rules: []config.Rule{{
				Host:      "api.warn.test",
				SecretRef: "op://Vault/Item/field",
				Inject: config.Inject{
					Type:     config.InjectTypeHeader,
					Name:     "x-api-key",
					Template: "static",
				},
			}},
		},
		Lints: []config.LintError{{
			Severity: config.SeverityWarning,
			Path:     "rules[0].inject.template",
			Message:  "missing placeholder",
		}},
	}

	require.Eventually(t, func() bool {
		_, ok := engine.Match("api.warn.test")
		return ok
	}, 2*time.Second, 10*time.Millisecond, "warning-only event must still swap")
}

// TestRunReloader_WarnsOnBaselineDrift confirms that an edit to cache_ttl
// (a field bound at startup, not hot-swappable) produces a Warn telling the
// user a restart is needed. Without this the disk and the running process
// diverge silently.
func TestRunReloader_WarnsOnBaselineDrift(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	baseline := &broker.Baseline{
		Proxy: config.Proxy{
			Listen:    "127.0.0.1:1701",
			CacheTTL:  15 * time.Minute,
			OnNoMatch: config.OnNoMatchPassthrough,
		},
		CredStores: []config.CredStore{{
			Name:  config.DefaultCredStoreName,
			Token: config.Token{Source: config.TokenSourceAuto, EnvVar: "OP_SERVICE_ACCOUNT_TOKEN"},
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, logger, baseline)
	}()
	t.Cleanup(func() {
		cancel()
		close(events)
		wg.Wait()
	})

	// Reload with the same rules but a different cache_ttl.
	events <- config.Event{
		New: &config.Config{
			Proxy: config.Proxy{
				Listen:    "127.0.0.1:1701",
				CacheTTL:  1 * time.Hour,
				OnNoMatch: config.OnNoMatchPassthrough,
			},
			CredStores: baseline.CredStores,
		},
	}

	require.Eventually(t, func() bool {
		s := logBuf.String()
		return strings.Contains(s, "config edit ignored") && strings.Contains(s, "cache_ttl")
	}, 2*time.Second, 10*time.Millisecond, "expected a Warn about cache_ttl drift; got %s", logBuf.String())
}

// TestRunReloader_WarnsOnMaxBodyBytesDrift confirms that editing the
// proxy-wide body cap (bound at startup, captured in the hook closure) trips a
// restart warning, mirroring the other boot-bound proxy fields.
func TestRunReloader_WarnsOnMaxBodyBytesDrift(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	baseline := &broker.Baseline{
		Proxy: config.Proxy{
			Listen:       "127.0.0.1:1701",
			CacheTTL:     15 * time.Minute,
			OnNoMatch:    config.OnNoMatchPassthrough,
			MaxBodyBytes: 1 << 20,
		},
		CredStores: []config.CredStore{{
			Name:  config.DefaultCredStoreName,
			Token: config.Token{Source: config.TokenSourceAuto, EnvVar: "OP_SERVICE_ACCOUNT_TOKEN"},
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, logger, baseline)
	}()
	t.Cleanup(func() {
		cancel()
		close(events)
		wg.Wait()
	})

	events <- config.Event{
		New: &config.Config{
			Proxy: config.Proxy{
				Listen:       "127.0.0.1:1701",
				CacheTTL:     15 * time.Minute,
				OnNoMatch:    config.OnNoMatchPassthrough,
				MaxBodyBytes: 8 << 20,
			},
			CredStores: baseline.CredStores,
		},
	}

	require.Eventually(t, func() bool {
		s := logBuf.String()
		return strings.Contains(s, "config edit ignored") && strings.Contains(s, "max_body_bytes")
	}, 2*time.Second, 10*time.Millisecond, "expected a Warn about max_body_bytes drift; got %s", logBuf.String())
}

// TestRunReloader_DoesNotWarnOnCredStoreReorder confirms that a cosmetic
// reorder of `credstores:` entries in YAML (semantically a no-op) does
// not trip the drift warning. Order-sensitivity here trains operators
// to ignore drift warnings; the comparison must be a multiset check.
func TestRunReloader_DoesNotWarnOnCredStoreReorder(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	original := []config.CredStore{
		{Name: "a", Provider: "op", Token: config.Token{Source: config.TokenSourceEnv, EnvVar: "A"}},
		{Name: "b", Provider: "op", Token: config.Token{Source: config.TokenSourceEnv, EnvVar: "B"}},
	}
	baseline := &broker.Baseline{
		Proxy: config.Proxy{
			Listen:    "127.0.0.1:1701",
			CacheTTL:  15 * time.Minute,
			OnNoMatch: config.OnNoMatchPassthrough,
		},
		CredStores: original,
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, logger, baseline)
	}()
	t.Cleanup(func() {
		cancel()
		close(events)
		wg.Wait()
	})

	// Same credstores, swapped order.
	reordered := []config.CredStore{original[1], original[0]}
	events <- config.Event{
		New: &config.Config{
			Proxy:      baseline.Proxy,
			CredStores: reordered,
		},
	}

	require.Eventually(t, func() bool {
		return strings.Contains(logBuf.String(), "config reload applied")
	}, 2*time.Second, 10*time.Millisecond, "reload should have applied; got %s", logBuf.String())

	require.NotContains(t, logBuf.String(), "credstores",
		"reordering credstores must not trip the drift warning; got %s", logBuf.String())
}

// TestRunReloader_WarnsOnCredStoreSettingsDrift confirms that editing a
// credstore's provider-interpreted `settings` (e.g. a self-hosted
// server_url) trips the drift warning. settings are consumed into the
// resolver at boot, so a change needs a restart to take effect — the same
// silent-divergence hazard as a token or provider edit.
func TestRunReloader_WarnsOnCredStoreSettingsDrift(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	baseline := &broker.Baseline{
		Proxy: config.Proxy{
			Listen:    "127.0.0.1:1701",
			CacheTTL:  15 * time.Minute,
			OnNoMatch: config.OnNoMatchPassthrough,
		},
		CredStores: []config.CredStore{{
			Name:     "bw",
			Provider: "bitwarden",
			Token:    config.Token{Source: config.TokenSourceEnv, EnvVar: "BWS_ACCESS_TOKEN"},
			Settings: map[string]string{"server_url": "https://vault.example.com"},
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		broker.RunReloader(ctx, engine, events, logger, baseline)
	}()
	t.Cleanup(func() {
		cancel()
		close(events)
		wg.Wait()
	})

	// Same credstore, different server_url.
	drifted := []config.CredStore{{
		Name:     "bw",
		Provider: "bitwarden",
		Token:    config.Token{Source: config.TokenSourceEnv, EnvVar: "BWS_ACCESS_TOKEN"},
		Settings: map[string]string{"server_url": "https://other.example.com"},
	}}
	events <- config.Event{
		New: &config.Config{Proxy: baseline.Proxy, CredStores: drifted},
	}

	require.Eventually(t, func() bool {
		s := logBuf.String()
		return strings.Contains(s, "config edit ignored") && strings.Contains(s, "credstores")
	}, 2*time.Second, 10*time.Millisecond, "expected a Warn about credstores drift; got %s", logBuf.String())
}

func TestRunReloader_ReturnsOnContextCancel(t *testing.T) {
	t.Parallel()

	engine := broker.NewEngine(nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan config.Event)

	done := make(chan struct{})
	go func() {
		broker.RunReloader(ctx, engine, events, logger, nil)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunReloader did not return on context cancel")
	}
}
