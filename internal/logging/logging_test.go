package logging_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/logging"
)

func TestNew_DefaultsToTextHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l, err := logging.New(logging.Options{NoColor: true, Output: &buf})
	require.NoError(t, err)
	l.Info("hello", slog.String("k", "v"))

	require.Contains(t, buf.String(), "hello")
	require.Contains(t, buf.String(), "k=v")
	require.NotContains(t, buf.String(), `"msg":"hello"`,
		"text handler must not emit JSON")
}

func TestNew_JSONHandlerEmitsJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l, err := logging.New(logging.Options{Format: "json", Output: &buf})
	require.NoError(t, err)
	l.Info("hello", slog.String("k", "v"))

	require.Contains(t, buf.String(), `"msg":"hello"`)
	require.Contains(t, buf.String(), `"k":"v"`)
}

func TestNew_LevelDebugAllowsDebugRecords(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l, err := logging.New(logging.Options{Level: "debug", Output: &buf})
	require.NoError(t, err)
	l.Debug("trace-me")
	require.Contains(t, buf.String(), "trace-me")
}

func TestNew_LevelInfoFiltersDebug(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l, err := logging.New(logging.Options{Level: "info", Output: &buf})
	require.NoError(t, err)
	l.Debug("invisible")
	l.Info("visible")
	require.NotContains(t, buf.String(), "invisible")
	require.Contains(t, buf.String(), "visible")
}

// quiet drops Info too — only Warn and Error make it through. The
// per-request match→resolve→inject triple is collapsed into a single
// Info-summary line elsewhere, but at the handler level quiet === Warn+.
func TestNew_LevelQuietDropsInfo(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l, err := logging.New(logging.Options{Level: "quiet", Output: &buf})
	require.NoError(t, err)
	l.Info("hidden")
	l.Warn("visible")
	require.NotContains(t, buf.String(), "hidden")
	require.Contains(t, buf.String(), "visible")
}

func TestNew_RejectsUnknownFormat(t *testing.T) {
	t.Parallel()

	_, err := logging.New(logging.Options{Format: "yaml"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "text|json")
}

func TestNew_RejectsUnknownLevel(t *testing.T) {
	t.Parallel()

	_, err := logging.New(logging.Options{Level: "trace"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "quiet|info|debug")
}

// NoColor=true must yield ANSI-free output. We check by piping through a
// scanner that asserts no ESC byte appears anywhere in the buffer.
func TestNew_NoColorStripsANSI(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	l, err := logging.New(logging.Options{NoColor: true, Output: &buf})
	require.NoError(t, err)
	l.Info("hello", slog.String("level", "info"))
	require.NotContains(t, buf.String(), "\x1b[", "ANSI escapes must be suppressed when NoColor=true")
}

// The NO_COLOR convention (https://no-color.org) takes precedence: setting
// the env var implies NoColor even if Options.NoColor is false.
func TestNew_NoColorHonorsEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	l, err := logging.New(logging.Options{Output: &buf})
	require.NoError(t, err)
	l.Info("hello")
	require.NotContains(t, buf.String(), "\x1b[", "NO_COLOR env must suppress ANSI escapes")
}

func TestNew_NilOutputDefaultsToStderr(t *testing.T) {
	t.Parallel()

	l, err := logging.New(logging.Options{})
	require.NoError(t, err)
	require.NotNil(t, l, "logger must be usable when Output is nil")
	// We can't easily intercept os.Stderr here without racing other tests;
	// the contract under test is just that nil Output doesn't panic on Log.
	require.NotPanics(t, func() { l.Info("ok") })
}

// Default behavior when the writer is not a TTY: no ANSI escapes. This
// prevents `postern server 2> server.log` (or any pipe) from filling the
// log with ESC[…m sequences. The previous slog.NewTextHandler default had
// this property; we preserve it for tint.
func TestNew_NonTTYDefaultsToNoColor(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer // *bytes.Buffer is not an *os.File → not a TTY
	l, err := logging.New(logging.Options{Output: &buf})
	require.NoError(t, err)
	l.Info("hi")
	require.NotContains(t, buf.String(), "\x1b[",
		"non-TTY writers must default to no-color output")
}
