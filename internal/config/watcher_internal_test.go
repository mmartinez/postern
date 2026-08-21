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
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/stretchr/testify/require"
)

const internalValidConfig = `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

const internalSecondValidConfig = `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.anthropic.com
    secret_ref: op://Agents/Anthropic/api_key
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
		require.Equal(t, "api.anthropic.com", ev.New.Rules[0].Host)
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
		require.Equal(t, "api.anthropic.com", ev.New.Rules[0].Host)
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
