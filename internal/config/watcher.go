package config

import (
	"context"
	"errors"
)

// ErrWatcherNotImplemented is returned by Watcher.Watch until T7 wires up the
// fsnotify-based hot reload path. The public surface is fixed in M1 so callers
// (the proxy runtime) can depend on it without churn when T7 lands.
var ErrWatcherNotImplemented = errors.New("config watcher not yet implemented (lands in T7)")

// Event is published when the watched config file changes on disk. New is the
// freshly-parsed config; Lints contains any validation findings discovered
// alongside the reload. When Lints contains a SeverityError entry the runtime
// should keep its prior config — T7 will enforce that.
type Event struct {
	New   *Config
	Lints []LintError
}

// Watcher streams Event values as the watched file changes. T7 will provide
// the fsnotify-backed implementation; until then NewWatcher returns a stub
// that surfaces ErrWatcherNotImplemented so callers fail loudly if they try
// to use it early.
type Watcher interface {
	Watch(ctx context.Context) (<-chan Event, error)
	Close() error
}

// NewWatcher returns the M1 stub Watcher. Path is accepted now to lock the
// constructor signature; the stub does not use it.
func NewWatcher(path string) Watcher {
	return &noopWatcher{path: path}
}

type noopWatcher struct {
	// path is unused in the stub but kept on the struct so T7's fsnotify
	// wiring slots in without an API change.
	path string //nolint:unused // reserved for T7
}

func (w *noopWatcher) Watch(_ context.Context) (<-chan Event, error) {
	return nil, ErrWatcherNotImplemented
}

func (w *noopWatcher) Close() error { return nil }
