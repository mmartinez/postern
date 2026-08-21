package config_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// writeAtomic mirrors what an editor does on save: write a sibling temp
// file and rename it over the target. fsnotify on Linux+macOS sees this
// as a Rename/Create rather than a Write, which is the exact path the
// Watcher must survive.
func writeAtomic(t *testing.T, path string, body []byte) {
	t.Helper()
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cfg-*")
	require.NoError(t, err)
	_, err = tmp.Write(body)
	require.NoError(t, err)
	require.NoError(t, tmp.Close())
	require.NoError(t, os.Rename(tmp.Name(), path))
}

// receiveEvent blocks until the next Watcher event or budget elapses.
func receiveEvent(t *testing.T, ch <-chan config.Event, budget time.Duration) config.Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(budget):
		t.Fatalf("no event within %s", budget)
		return config.Event{}
	}
}

const watchedValidConfig = `
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

const watchedSecondValidConfig = `
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

func TestWatcher_EmitsEventOnValidEdit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))

	w := config.NewWatcher(path)
	t.Cleanup(func() { _ = w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	events, err := w.Watch(ctx)
	require.NoError(t, err)

	// Replace with a different valid config — debounce keeps it to one event.
	writeAtomic(t, path, []byte(watchedSecondValidConfig))

	ev := receiveEvent(t, events, 3*time.Second)
	require.NotNil(t, ev.New)
	require.Empty(t, ev.Lints, "valid edit should emit no lints")
	require.Len(t, ev.New.Rules, 1)
	require.Equal(t, "api.anthropic.com", ev.New.Rules[0].Host)
}

func TestWatcher_EmitsLintsOnInvalidEdit(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))

	w := config.NewWatcher(path)
	t.Cleanup(func() { _ = w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	events, err := w.Watch(ctx)
	require.NoError(t, err)

	// Write a YAML with a syntactic schema error (bad secret_ref).
	badConfig := []byte(`
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: not-a-valid-op-ref
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`)
	writeAtomic(t, path, badConfig)

	ev := receiveEvent(t, events, 3*time.Second)
	require.NotEmpty(t, ev.Lints, "invalid edit must surface lints")

	var fatal bool
	for _, l := range ev.Lints {
		if l.Severity == config.SeverityError {
			fatal = true
		}
	}
	require.True(t, fatal, "expected at least one fatal lint; got %v", ev.Lints)
}

func TestWatcher_DebouncesRapidEdits(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))

	w := config.NewWatcher(path)
	t.Cleanup(func() { _ = w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	events, err := w.Watch(ctx)
	require.NoError(t, err)

	// Three rapid writes inside the debounce window should coalesce to one
	// emitted event with the latest content.
	for i := 0; i < 3; i++ {
		require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))
	}
	writeAtomic(t, path, []byte(watchedSecondValidConfig))

	ev := receiveEvent(t, events, 3*time.Second)
	require.Equal(t, "api.anthropic.com", ev.New.Rules[0].Host, "final emitted event must reflect last write")

	// No further events for the next 200ms (more than the 100ms debounce).
	select {
	case extra := <-events:
		t.Fatalf("unexpected extra event after debounce: %+v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestWatcher_ClosesCleanly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))

	w := config.NewWatcher(path)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	events, err := w.Watch(ctx)
	require.NoError(t, err)
	require.NoError(t, w.Close())

	// After Close the channel must close so consumers can drain without
	// hanging on shutdown.
	select {
	case _, ok := <-events:
		require.False(t, ok, "events channel must close after Close()")
	case <-time.After(1 * time.Second):
		t.Fatal("events channel did not close within 1s of Close()")
	}
}

// TestWatcher_RecoversAfterWatchDeath covers the silent-death failure mode:
// fsnotify removes a parent-directory watch without emitting any error when
// the directory itself is deleted or replaced (IN_IGNORED / IN_DELETE_SELF).
// The watcher keeps looking healthy but no events ever arrive again. The
// stat-poll fallback must notice the next edit and still fire a reload.
func TestWatcher_RecoversAfterWatchDeath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))

	w := config.NewWatcher(path)
	t.Cleanup(func() { _ = w.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	events, err := w.Watch(ctx)
	require.NoError(t, err)

	// Replace the watched directory out from under the watcher. The
	// inotify watch dies silently; nothing is delivered afterwards.
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.Mkdir(dir, 0o700))
	writeAtomic(t, path, []byte(watchedSecondValidConfig))

	// Bound: one poll interval to notice, plus the debounce window, plus
	// scheduler slack. A tick landing inside the delete/recreate window can
	// surface a transient missing-file lint first, so drain until the real
	// reload arrives.
	deadline := time.After(8 * time.Second) // one poll interval (5s) + debounce (100ms) + slack
	for {
		select {
		case ev := <-events:
			if ev.New == nil {
				continue // transient unreadable-file lint; keep waiting
			}
			require.Len(t, ev.New.Rules, 1)
			require.Equal(t, "api.anthropic.com", ev.New.Rules[0].Host)
			return
		case <-deadline:
			t.Fatal("no reload event after watch death and edit")
		}
	}
}
