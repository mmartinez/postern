package logging

import (
	"context"
	"log/slog"
)

// summaryAttrKey marks a record as a per-request summary. The summary
// handler bypasses the inner level filter for these records so they
// surface even in quiet mode (where Info-level per-stage chatter is
// filtered), then strips the marker before delegating so the key never
// appears in operator-facing output.
//
// Plain Info records never carry this key in production: only Summary
// adds it, and the marker is recognised only when the attr value is the
// bool `true`. A user-emitted slog.Bool("_summary", false) is therefore
// not a marker — it round-trips as an ordinary attribute.
const summaryAttrKey = "_summary"

// Summary emits a per-request lifecycle line. The line passes through in
// every level (info, debug, and quiet) so operators see exactly one
// summary record per request regardless of verbosity; the per-stage
// chatter that surrounds it is only visible at info/debug because of the
// inner level filter.
//
// Callers pass the same shape they would to logger.Info — Summary just
// stamps the record with the summary marker before forwarding it. The
// marker is stripped from output by the handler.
func Summary(ctx context.Context, l *slog.Logger, msg string, attrs ...slog.Attr) {
	all := make([]slog.Attr, 0, len(attrs)+1)
	all = append(all, slog.Bool(summaryAttrKey, true))
	all = append(all, attrs...)
	l.LogAttrs(ctx, slog.LevelInfo, msg, all...)
}

// summaryHandler wraps a slog.Handler with the project's per-request
// summary contract:
//
//   - Records at Warn or higher always pass through.
//   - Records carrying the summary marker pass through regardless of the
//     inner handler's level (so quiet mode still shows one summary line
//     per request). The marker is stripped before forwarding so it never
//     appears in serialized output.
//   - Other records below Warn defer to the inner handler's level filter.
type summaryHandler struct {
	inner slog.Handler
}

func newSummaryHandler(inner slog.Handler) slog.Handler {
	return &summaryHandler{inner: inner}
}

// Enabled returns true for any level because Handle does the actual
// filtering — summary records may arrive at Info even when the inner
// handler is at Warn (quiet mode), so we cannot short-circuit on level
// alone. The cost is that callers gated by Enabled (e.g. `if l.Enabled(…)
// { build heavy attrs }`) pay the construction cost when the record
// would otherwise be dropped. The trade is worth it: missing a summary
// line is a correctness failure; building one extra Record per dropped
// log call is a performance wart.
func (h *summaryHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *summaryHandler) Handle(ctx context.Context, r slog.Record) error {
	if isSummary(r) {
		return h.inner.Handle(ctx, recordWithoutMarker(r))
	}
	if r.Level >= slog.LevelWarn {
		return h.inner.Handle(ctx, r)
	}
	if !h.inner.Enabled(ctx, r.Level) {
		return nil
	}
	return h.inner.Handle(ctx, r)
}

func (h *summaryHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &summaryHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *summaryHandler) WithGroup(name string) slog.Handler {
	return &summaryHandler{inner: h.inner.WithGroup(name)}
}

// isSummary reports whether r carries the summary marker. The marker is
// specifically slog.Bool(summaryAttrKey, true) — a user-emitted
// slog.Bool(summaryAttrKey, false) does not match, so the key collision
// surface is narrower than "any attr with this name".
func isSummary(r slog.Record) bool {
	marked := false
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == summaryAttrKey && a.Value.Kind() == slog.KindBool && a.Value.Bool() {
			marked = true
			return false
		}
		return true
	})
	return marked
}

// recordWithoutMarker copies r minus the summary marker attribute. We
// build a fresh slog.Record because slog.Record's attribute storage is
// not mutable in-place; the marker would otherwise be serialized by the
// inner handler.
func recordWithoutMarker(r slog.Record) slog.Record {
	out := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == summaryAttrKey && a.Value.Kind() == slog.KindBool && a.Value.Bool() {
			return true
		}
		out.AddAttrs(a)
		return true
	})
	return out
}
