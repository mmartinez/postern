// Package logging assembles the *slog.Logger postern uses everywhere.
// It chooses between the vendored tint handler (human-readable, ANSI
// coloured) and slog.JSONHandler based on caller-supplied options, and
// applies the project's CLI-level convention for levels (quiet/info/debug)
// and the NO_COLOR env-var contract.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/mmartinez/postern/internal/logging/tint"
)

// Options configures New. Zero values pick sane defaults (text, info,
// auto-detect-colour, stderr).
type Options struct {
	// Format is the wire format: "text" (default) or "json".
	Format string
	// Level is the minimum severity to emit. Values:
	//
	//   - "quiet" — Warn and above (per-stage Info chatter is dropped).
	//     Records emitted via Summary still pass through at Info because
	//     they carry the per-request lifecycle line operators need to see
	//     even in quiet mode.
	//   - "info"  — Info and above (the default).
	//   - "debug" — everything.
	Level string
	// NoColor disables ANSI colouring in the text handler. Precedence:
	//   1. NO_COLOR env var set to any non-empty value → disable colour
	//      (no-color.org spec — env wins over flag).
	//   2. Explicit NoColor=true → disable colour.
	//   3. Otherwise, colour iff Output is a character device (TTY); pipes
	//      and regular files default to plain text so redirected logs are
	//      grep-friendly.
	// The flag has no effect on the JSON handler.
	NoColor bool
	// Output is the writer log records are emitted to; defaults to
	// os.Stderr when nil. The CLI passes the cobra command's ErrOrStderr.
	Output io.Writer
}

// New returns a slog.Logger configured per opts. Bad Format / Level
// values surface as errors so cobra's RunE can fail the command instead
// of silently degrading to defaults.
func New(opts Options) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}
	w := opts.Output
	if w == nil {
		w = os.Stderr
	}

	var base slog.Handler
	switch opts.Format {
	case "", "text":
		base = tint.NewHandler(w, &tint.Options{
			Level:   level,
			NoColor: shouldDisableColor(w, opts.NoColor),
		})
	case "json":
		base = slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	default:
		return nil, fmt.Errorf("unknown --log-format %q (want text|json)", opts.Format)
	}
	// The summary wrapper bypasses the inner level filter for records
	// carrying the per-request summary marker and strips the marker
	// before output. It also re-checks the inner level for non-summary
	// records so the inner handler's level field stays authoritative.
	return slog.New(newSummaryHandler(base)), nil
}

// parseLevel maps the CLI vocabulary onto slog.Level. quiet is Warn so
// the per-request Info chatter the broker emits at info-level is
// suppressed; the summary wrapper lets Summary-marked Info records
// through regardless of this level so the operator still sees one
// per-request lifecycle line.
func parseLevel(s string) (slog.Level, error) {
	switch s {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "quiet":
		return slog.LevelWarn, nil
	default:
		return 0, fmt.Errorf("unknown --log-level %q (want quiet|info|debug)", s)
	}
}

// shouldDisableColor implements the NoColor precedence ladder. The
// NO_COLOR env var (no-color.org) is checked first because the spec
// treats it as a strong user opt-out — any non-empty value disables
// colour regardless of the flag. After that we honour an explicit
// NoColor=true. Falling through, we auto-detect: if the writer is a
// terminal (character-device file) we keep colour on, otherwise off.
func shouldDisableColor(w io.Writer, explicit bool) bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	if explicit {
		return true
	}
	return !isTerminal(w)
}

// isTerminal reports whether w is a terminal-attached file descriptor.
// Returns false for non-*os.File writers (bytes.Buffer in tests, pipes,
// io.MultiWriter, ...) so colour stays off whenever auto-detection
// can't see a TTY.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
