package config

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// debounceWindow coalesces bursty editor saves into a single reload. Most
// editors emit a Rename → Create → Write sequence (atomic save) or several
// Writes (in-place save); 100ms is long enough to merge those without
// adding user-visible latency.
const debounceWindow = 100 * time.Millisecond

// pollInterval is how often the stat-poll fallback re-checks the watched
// file. It runs unconditionally alongside the fsnotify watch so that both
// inotify queue overflow (events lost) and silent watch death (the kernel
// drops the parent-directory watch when it is replaced or removed, with no
// error reported) still converge on a reload.
const pollInterval = 5 * time.Second

// ErrWatcherNotImplemented is retained for backwards compatibility with the
// stub Watcher's signature. The fsnotify-backed implementation never
// returns it, but consumers that conditionally branch on the sentinel keep
// compiling.
var ErrWatcherNotImplemented = errors.New("config watcher not implemented")

// Event is published when the watched config file changes on disk. New is
// the freshly-parsed config (nil only if the file became unreadable);
// Lints is the slice of findings discovered alongside the reload. A
// SeverityError entry in Lints tells the runtime to keep its prior config
// — the watcher always emits so callers can log what was rejected.
type Event struct {
	New   *Config
	Lints []LintError
}

// Watcher streams Event values as the watched file changes.
type Watcher interface {
	Watch(ctx context.Context) (<-chan Event, error)
	Close() error
}

// NewWatcher returns a Watcher that observes path. The underlying fsnotify
// watcher is bound to the parent directory (not the file) so atomic-save
// flows (rename-over-target) survive without the watch dropping. fsnotify
// errors are discarded; use NewWatcherWithLogger to surface them.
//
// path is absolutised eagerly so the watcher does not silently track CWD
// drift if the process chdirs (or if the user passed a bare filename from
// a busy directory). filepath.Abs failures fall back to the input verbatim
// — the subsequent fsnotify.Add will surface the underlying error.
func NewWatcher(path string) Watcher {
	return NewWatcherWithLogger(path, nil)
}

// NewWatcherWithLogger behaves like NewWatcher and additionally wires
// logger into the watcher so fsnotify errors (e.g. inotify queue overflow)
// are surfaced at Warn level instead of dropped. A nil logger discards all
// output.
func NewWatcherWithLogger(path string, logger *slog.Logger) Watcher {
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	return &fsWatcher{path: path, logger: logger}
}

type fsWatcher struct {
	path   string
	logger *slog.Logger

	// Test hooks, nil/zero in production: statFn substitutes the stat
	// read and tickInterval overrides pollInterval (scripting deterministic
	// change interleavings); afterEmit runs between an emission and the
	// post-emission stat — the exact window where a racing edit would
	// otherwise be silently absorbed into the baseline.
	statFn       func(path string) (statSnapshot, bool)
	tickInterval time.Duration
	afterEmit    func()

	mu       sync.Mutex
	fsw      *fsnotify.Watcher
	events   chan Event
	cancel   context.CancelFunc
	closed   bool
	closeCh  chan struct{}
	pumpDone chan struct{}
}

func (w *fsWatcher) Watch(parent context.Context) (<-chan Event, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fsw != nil {
		return nil, errors.New("watcher already started")
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create fsnotify watcher: %w", err)
	}
	if err := fsw.Add(filepath.Dir(w.path)); err != nil {
		_ = fsw.Close()
		return nil, fmt.Errorf("watch %s: %w", filepath.Dir(w.path), err)
	}
	return w.startLocked(parent, fsw)
}

// startLocked finishes wiring and launches pump. It expects w.mu held and is
// split out so tests can inject a bare fsnotify watcher (e.g. one with no
// registered watches, to exercise the stat-poll fallback in isolation).
func (w *fsWatcher) startLocked(parent context.Context, fsw *fsnotify.Watcher) (<-chan Event, error) {
	ctx, cancel := context.WithCancel(parent)
	out := make(chan Event, 1)
	w.fsw = fsw
	w.events = out
	w.cancel = cancel
	w.closeCh = make(chan struct{})
	w.pumpDone = make(chan struct{})

	// Seed the poll fingerprint synchronously so an edit racing Watch's
	// return cannot be absorbed into the baseline and missed by the ticker.
	seed, seedOK := w.statFile()
	go w.pump(ctx, seed, seedOK)
	return out, nil
}

// statFile reads the watched file's poll fingerprint through statFn when a
// test installed one, and through the real stat otherwise.
func (w *fsWatcher) statFile() (statSnapshot, bool) {
	if w.statFn != nil {
		return w.statFn(w.path)
	}
	return statSnapshotOf(w.path)
}

// pump is the long-lived goroutine that converts fsnotify events on the
// parent directory into debounced Event values on the output channel. A
// stat-poll ticker runs alongside the event stream so changes are still
// detected when fsnotify events are lost to queue overflow or the watch
// dies silently (the kernel removes a parent-directory watch on
// IN_IGNORED/IN_DELETE_SELF without emitting an error). It exits when the
// context is cancelled, Close is called, or the underlying fsnotify watcher
// errors out fatally.
func (w *fsWatcher) pump(ctx context.Context, last statSnapshot, lastOK bool) {
	defer close(w.pumpDone)
	defer close(w.events)

	log := w.logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	target := filepath.Clean(w.path)
	var timer *time.Timer
	var timerCh <-chan time.Time
	armDebounce := func() {
		if timer == nil {
			timer = time.NewTimer(debounceWindow)
		} else {
			if !timer.Stop() {
				// Drain a stale firing if one is already buffered.
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(debounceWindow)
		}
		timerCh = timer.C
	}
	// Stop a pending debounce so we don't leak its timer slot into the
	// runtime's wheel after the pump goroutine exits.
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	interval := w.tickInterval
	if interval <= 0 {
		interval = pollInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.closeCh:
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			if filepath.Clean(ev.Name) != target {
				continue
			}
			// Any event that touches the file (Write, Create after atomic
			// rename, Chmod from editors that bump perms on save) is a
			// signal to debounce-and-reload.
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) != 0 {
				armDebounce()
			}
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			// fsnotify Errors are usually transient (Linux inotify queue
			// overflow under filesystem pressure). Surface them: overflow
			// means events were lost and only the stat poll below will
			// recover the missed change. We deliberately do NOT arm the
			// debounce here: under sustained pressure a stream of errors
			// could otherwise reset the timer indefinitely and starve a
			// legitimate reload.
			log.Warn("config watcher error", slog.Any("err", err))
		case <-ticker.C:
			cur, ok := w.statFile()
			if ok != lastOK || cur != last {
				last, lastOK = cur, ok
				armDebounce()
			}
		case <-timerCh:
			timerCh = nil
			// Snapshot before reading so the baseline can only advance to
			// a fingerprint whose content this emission actually read.
			pre, preOK := w.statFile()
			w.emitReload(ctx)
			if w.afterEmit != nil {
				w.afterEmit()
			}
			if post, postOK := w.statFile(); postOK != preOK || post != pre {
				// The file changed while emitting. Leave the baseline at
				// the last emitted state and re-arm: the newer version
				// must be emitted too, never silently absorbed into the
				// baseline.
				armDebounce()
			} else {
				last, lastOK = pre, preOK
			}
		}
	}
}

// emitReload reads the watched file, validates it, and pushes the result
// onto the output channel. It is non-blocking: if the consumer is slow the
// pending event is dropped in favour of the freshest one. That matches the
// "reflect the file's current state" contract a hot-reload watcher must
// honour; a stale event is worse than no event.
func (w *fsWatcher) emitReload(ctx context.Context) {
	cfg, lints, err := LoadFile(w.path)
	if err != nil {
		// Surface the read/parse error as a single fatal lint so the runtime
		// can log it and keep the previous config without dereferencing nil.
		lints = append(lints, LintError{
			Severity: SeverityError,
			Path:     "(file)",
			Message:  fmt.Sprintf("reload %s: %v", w.path, err),
		})
	}
	ev := Event{New: cfg, Lints: lints}

	select {
	case w.events <- ev:
	default:
		// Channel full — drop the previously buffered event and replace it
		// so the consumer always sees the latest reload result.
		select {
		case <-w.events:
		default:
		}
		select {
		case w.events <- ev:
		case <-ctx.Done():
		}
	}
}

func (w *fsWatcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	closeCh := w.closeCh
	cancel := w.cancel
	fsw := w.fsw
	pumpDone := w.pumpDone
	w.mu.Unlock()

	if closeCh != nil {
		close(closeCh)
	}
	if cancel != nil {
		cancel()
	}
	var err error
	if fsw != nil {
		err = fsw.Close()
	}
	if pumpDone != nil {
		<-pumpDone
	}
	return err
}
