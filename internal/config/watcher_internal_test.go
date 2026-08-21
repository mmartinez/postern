package config

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
)

const internalValidConfig = `
token:
  source: env
  env_var: SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.one.example
    secret_ref: op://vault/items/one/credential
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

const internalSecondValidConfig = `
token:
  source: env
  env_var: SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.two.example
    secret_ref: op://vault/items/two/credential
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

// syncBuffer is a goroutine-safe bytes.Buffer: the pump writes to it while
// the test reads, and -race flags unsynchronized access.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// TestWatcher_LogsFsnotifyErrors injects a synthetic error the way the
// inotify backend would (e.g. ErrEventOverflow) and asserts it is surfaced
// at Warn level and that the pump goroutine survives to keep reloading.
func TestWatcher_LogsFsnotifyErrors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(internalValidConfig), 0o600))

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	w := &fsWatcher{path: path, logger: logger}
	fsw, err := fsnotify.NewWatcher()
	require.NoError(t, err)
	t.Cleanup(func() { _ = fsw.Close() })

	events, err := w.startLocked(ctx, fsw)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })

	synthetic := fmt.Errorf("synthetic: %w", fsnotify.ErrEventOverflow)
	select {
	case fsw.Errors <- synthetic:
	case <-time.After(time.Second):
		t.Fatal("pump did not consume the injected error within 1s")
	}

	require.Eventually(t, func() bool {
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "config watcher error") &&
				strings.Contains(line, "level=WARN") &&
				strings.Contains(line, "synthetic") {
				return true
			}
		}
		return false
	}, 2*time.Second, 10*time.Millisecond, "expected a Warn log for the injected error; got %q", buf.String())

	// The pump must still be alive: a subsequent edit still reloads.
	require.NoError(t, os.WriteFile(path, []byte(internalSecondValidConfig), 0o600))
	select {
	case ev := <-events:
		require.NotNil(t, ev.New)
		require.Equal(t, "api.two.example", ev.New.Rules[0].Host)
	case <-time.After(pollInterval + debounceWindow + 3*time.Second):
		t.Fatal("pump died after fsnotify error: no reload event")
	}
}

// TestWatcher_PollFallbackWithoutFsnotifyEvents starts the watcher against a
// bare fsnotify watcher with no registered watches, so its Events channel
// never delivers anything. A file modification must still produce a reload
// via the stat-poll fallback alone.
func TestWatcher_PollFallbackWithoutFsnotifyEvents(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(internalValidConfig), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	fsw, err := fsnotify.NewWatcher() // no watches registered: Events never fires
	require.NoError(t, err)
	t.Cleanup(func() { _ = fsw.Close() })

	w := &fsWatcher{path: path}
	events, err := w.startLocked(ctx, fsw)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })

	require.NoError(t, os.WriteFile(path, []byte(internalSecondValidConfig), 0o600))

	select {
	case ev := <-events:
		require.NotNil(t, ev.New)
		require.Empty(t, ev.Lints, "valid edit should emit no lints")
		require.Equal(t, "api.two.example", ev.New.Rules[0].Host)
	case <-time.After(pollInterval + debounceWindow + 3*time.Second):
		t.Fatal("stat-poll fallback did not fire a reload after a silent edit")
	}

	// No duplicate emission at the following tick: the poll fingerprint was
	// refreshed when the reload was emitted.
	select {
	case extra := <-events:
		t.Fatalf("unexpected duplicate reload event: %+v", extra)
	case <-time.After(pollInterval + 500*time.Millisecond):
	}
}

// TestWatcher_NoLostUpdateAcrossEmission reproduces, deterministically, the
// interleaving where an edit lands after emitReload reads the file but
// before the post-emission stat refreshes the poll baseline: the afterEmit
// hook writes the new version inside exactly that window. The invariant
// under test: every fingerprint admitted into the baseline belongs to a
// version whose content was actually emitted — a version landing
// mid-emission must be re-armed and emitted, never swallowed as "seen".
func TestWatcher_NoLostUpdateAcrossEmission(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(internalValidConfig), 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	fsw, err := fsnotify.NewWatcher() // no watches registered: stat poll drives everything
	require.NoError(t, err)
	t.Cleanup(func() { _ = fsw.Close() })

	const thirdConfig = `
token:
  source: env
  env_var: SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.three.example
    secret_ref: op://vault/items/three/credential
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

	// tickInterval (500ms) > debounceWindow (100ms): the detection tick and
	// the emission never overlap, keeping the event order deterministic.
	var sneaked atomic.Bool
	w := &fsWatcher{path: path, tickInterval: 500 * time.Millisecond}
	w.afterEmit = func() {
		if sneaked.CompareAndSwap(false, true) {
			if err := os.WriteFile(path, []byte(thirdConfig), 0o600); err != nil {
				t.Errorf("hook write failed: %v", err)
			}
		}
	}

	events, err := w.startLocked(ctx, fsw)
	require.NoError(t, err)
	t.Cleanup(func() { _ = w.Close() })

	// The poll baseline is seeded synchronously inside startLocked, so an
	// edit written now is guaranteed to be a detected change, not baseline.
	require.NoError(t, os.WriteFile(path, []byte(internalSecondValidConfig), 0o600))

	ev := <-events
	require.NotNil(t, ev.New)
	require.Equal(t, "api.two.example", ev.New.Rules[0].Host,
		"first emission must carry the content read at emission time")

	// The version written inside the post-emission window must surface as
	// its own reload; the buggy baseline refresh absorbed it unemitted and
	// this receive timed out.
	select {
	case ev := <-events:
		require.NotNil(t, ev.New)
		require.Equal(t, "api.three.example", ev.New.Rules[0].Host,
			"mid-emission edit must be emitted, not absorbed into the baseline")
	case <-time.After(3 * time.Second):
		t.Fatal("update landing across the emission boundary was lost")
	}
}
