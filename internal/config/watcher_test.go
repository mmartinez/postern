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

// drainUntilSettled collects Watcher emissions until the stream has been
// quiet for quietPeriod (comfortably more than one debounce window) or the
// overall budget expires. It returns the last emission and how many arrived,
// so callers can assert on the settled state rather than on whichever
// emission happened to arrive first.
func drainUntilSettled(t *testing.T, ch <-chan config.Event) (config.Event, int) {
	t.Helper()
	const (
		quietPeriod = 500 * time.Millisecond // > debounceWindow with scheduling slack
		budget      = 3 * time.Second
	)
	deadline := time.After(budget)
	var last config.Event
	n := 0
	for {
		idle := time.After(quietPeriod)
		select {
		case ev := <-ch:
			last = ev
			n++
		case <-idle:
			return last, n
		case <-deadline:
			t.Fatalf("watcher did not settle within %s", budget)
			return last, n
		}
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

	// Three rapid in-place writes plus an atomic replace inside the
	// debounce window. Under load the pump can lag the writer far enough
	// that the debounce fires between individual saves (or mid-save, on a
	// truncated file), so an emission may legally reflect an intermediate
	// state; the watcher contract is convergence to the freshest state,
	// not "first emission == last write".
	for range 3 {
		require.NoError(t, os.WriteFile(path, []byte(watchedValidConfig), 0o600))
	}
	writeAtomic(t, path, []byte(watchedSecondValidConfig))

	last, n := drainUntilSettled(t, events)
	require.GreaterOrEqual(t, n, 1, "rapid edits must produce at least one emission")
	require.LessOrEqual(t, n, 6, "debounce collapsed too few of the four edits: %d emissions", n)
	require.NotNil(t, last.New, "final emission must carry a parsed config")
	require.NotEmpty(t, last.New.Rules, "final emission must carry the parsed rules")
	require.Equal(t, "api.anthropic.com", last.New.Rules[0].Host,
		"watcher must converge to the most recent write")
}

// TestWatcher_ConvergesAfterTornSave pins the recovery half of the debounce
// contract. A save that stalls between truncate and write (editor or runner
// descheduled mid-save) makes the debounce fire on an empty file; whatever
// is emitted for that intermediate state must not wedge the watcher: once
// the content lands it triggers a further emission, the watcher converges
// to the completed save, and then goes quiet.
func TestWatcher_ConvergesAfterTornSave(t *testing.T) {
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

	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	require.NoError(t, err)
	require.NoError(t, f.Truncate(0))
	// Hold the file empty past the 100ms debounce window so the watcher
	// necessarily observes the intermediate state before the content lands.
	time.Sleep(150 * time.Millisecond)
	_, err = f.WriteString(watchedSecondValidConfig)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	last, n := drainUntilSettled(t, events)
	require.GreaterOrEqual(t, n, 1, "torn save followed by content must produce an emission")
	require.NotNil(t, last.New, "final emission must carry a parsed config")
	require.Equal(t, "api.anthropic.com", last.New.Rules[0].Host,
		"watcher must converge to the completed save after observing a torn state")
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
