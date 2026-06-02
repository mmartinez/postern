package logging_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/logging"
)

func captureInfo(t *testing.T, opts logging.Options) (*slog.Logger, func() string) {
	t.Helper()
	var buf bytes.Buffer
	opts.Output = &buf
	opts.NoColor = true
	l, err := logging.New(opts)
	require.NoError(t, err)
	return l, buf.String
}

// Summary records are first-class in every mode: the per-stage
// proxy-request / broker-injected lines are still visible in info/debug,
// AND the Summary line passes through. In quiet, the Summary
// is the only Info-level line that survives the level filter; in info,
// the per-stage chatter accompanies the Summary. The marker is stripped
// from output either way (covered by sibling tests).
func TestLogger_SummaryAlongsidePerStageAtInfo(t *testing.T) {
	t.Parallel()

	l, out := captureInfo(t, logging.Options{Level: "info"})
	l.Info("proxy request", slog.String("method", "POST"))
	logging.Summary(context.Background(), l, "proxy response",
		slog.String("host", "api.example.com"),
		slog.Int("status", 200),
	)

	s := out()
	require.Contains(t, s, "proxy request")
	require.Contains(t, s, "proxy response")
}

// In quiet mode the per-stage chatter is filtered (Warn+), and only the
// summary line gets through — one line per request, regardless of how
// many stages emitted along the way.
func TestLogger_KeepsSummaryAtQuiet(t *testing.T) {
	t.Parallel()

	l, out := captureInfo(t, logging.Options{Level: "quiet"})
	l.Info("proxy request", slog.String("method", "POST"))
	logging.Summary(context.Background(), l, "request handled",
		slog.String("host", "api.example.com"),
		slog.Int("status", 200),
	)
	l.Info("proxy response", slog.Int("status", 200))

	s := out()
	require.NotContains(t, s, "proxy request")
	require.NotContains(t, s, "proxy response")
	require.Contains(t, s, "request handled")
	require.Contains(t, s, "host=api.example.com")
	require.Contains(t, s, "status=200")
	require.Equal(t, 1, strings.Count(s, "\n"),
		"quiet mode should emit exactly one log line per Summary call")
	require.NotContains(t, s, "_summary",
		"the marker attribute is internal and must not leak to user-facing output")
}

// In info mode the summary record passes through (it's the single
// response-side line in production); the marker is still stripped so
// operators don't see the internal control attribute.
func TestLogger_KeepsSummaryAtInfoWithoutMarker(t *testing.T) {
	t.Parallel()

	l, out := captureInfo(t, logging.Options{Level: "info"})
	logging.Summary(context.Background(), l, "proxy response",
		slog.String("host", "api.example.com"),
		slog.Int("status", 200),
	)

	s := out()
	require.Contains(t, s, "proxy response")
	require.Contains(t, s, "host=api.example.com")
	require.NotContains(t, s, "_summary",
		"the marker attribute is internal and must not leak to user-facing output")
}

// A user-emitted record carrying `_summary=false` (not the marker; just
// happens to share the key) must NOT be treated as a summary. Defensive
// against future contributors picking the same attr name.
func TestLogger_DistinguishesMarkerFromUserAttr(t *testing.T) {
	t.Parallel()

	l, out := captureInfo(t, logging.Options{Level: "info"})
	l.Info("user info", slog.Bool("_summary", false), slog.String("note", "diag"))

	s := out()
	require.Contains(t, s, "user info",
		"_summary=false is not the marker; the record must pass through")
	require.Contains(t, s, "note=diag")
}

// Warn/Error records always reach the handler, regardless of level. The
// summary wrapper must not swallow them.
func TestLogger_QuietKeepsWarnAndError(t *testing.T) {
	t.Parallel()

	l, out := captureInfo(t, logging.Options{Level: "quiet"})
	l.Warn("config drift")
	l.Error("upstream timeout")

	s := out()
	require.Contains(t, s, "config drift")
	require.Contains(t, s, "upstream timeout")
}

// Same contract under the JSON handler: summary records pass through in
// every level, and the marker key never appears in serialized output.
func TestLogger_SummaryWorksInJSONFormat(t *testing.T) {
	t.Parallel()

	for _, level := range []string{"info", "quiet"} {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			l, err := logging.New(logging.Options{Format: "json", Level: level, Output: &buf})
			require.NoError(t, err)
			logging.Summary(context.Background(), l, "request handled", slog.Int("status", 200))
			require.Contains(t, buf.String(), `"msg":"request handled"`)
			require.Contains(t, buf.String(), `"status":200`)
			require.NotContains(t, buf.String(), `"_summary"`,
				"marker key must not be serialized to JSON output")
		})
	}
}
