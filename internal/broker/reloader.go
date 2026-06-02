package broker

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"slices"

	"github.com/mmartinez/postern/internal/config"
)

// Baseline captures the proxy + credstore fields that were live when the
// server started. Only Engine rules are hot-swappable; cache_ttl and
// credstore settings (token sources, provider list) are bound at boot.
// The reloader uses Baseline to warn when an edit touches a field that
// requires a restart, so the user has a clear signal instead of a silent
// disk-vs-running divergence.
type Baseline struct {
	Proxy      config.Proxy
	CredStores []config.CredStore
}

// RunReloader consumes Watcher events and atomically swaps engine's
// ruleset whenever a valid reload arrives. Events carrying any
// SeverityError lint are logged and dropped: the engine continues
// serving its previous ruleset rather than dropping to an empty
// (passthrough-only) state on a typo. Warning-level lints are
// surfaced at INFO and do not block the swap.
//
// When baseline is non-nil and a clean reload's proxy/token fields
// differ from the baseline values, the reloader emits a Warn so the
// operator knows those edits won't take effect without a restart.
//
// RunReloader returns when ctx is cancelled or when events closes.
// Construct it in a dedicated goroutine after wiring the watcher; the
// CLI server command owns that orchestration.
func RunReloader(ctx context.Context, engine *Engine, events <-chan config.Event, logger *slog.Logger, baseline *Baseline) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			applyReload(engine, ev, logger, baseline)
		}
	}
}

// applyReload is the per-event decision: swap on clean reload, log + skip
// on fatal lint, and surface warnings without blocking the swap.
func applyReload(engine *Engine, ev config.Event, logger *slog.Logger, baseline *Baseline) {
	fatal := countFatal(ev.Lints)
	if fatal > 0 {
		logger.Warn("config reload rejected",
			slog.Int("fatal_lints", fatal),
			slog.Any("lints", lintStrings(ev.Lints)),
		)
		return
	}
	if ev.New == nil {
		logger.Warn("config reload rejected", slog.String("reason", "no config attached to event"))
		return
	}
	newRules, err := FromConfigRules(ev.New.Rules)
	if err != nil {
		logger.Warn("config reload rejected",
			slog.String("reason", "translate rules"),
			slog.Any("err", err),
		)
		return
	}
	engine.Swap(newRules)
	logger.Info("config reload applied", slog.Int("rules", len(newRules)))

	if warn := len(ev.Lints); warn > 0 {
		logger.Info("config reload applied with warnings",
			slog.Any("lints", lintStrings(ev.Lints)),
		)
	}

	if baseline != nil {
		warnDriftedFields(ev.New, *baseline, logger)
	}
}

// warnDriftedFields surfaces edits to proxy/token fields that the engine
// swap path does not pick up. Without this signal the user sees "config
// reload applied" and assumes their cache_ttl/token change took effect.
func warnDriftedFields(reloaded *config.Config, baseline Baseline, logger *slog.Logger) {
	if reloaded.Proxy.CacheTTL != baseline.Proxy.CacheTTL {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.cache_ttl"),
			slog.String("reason", "cache_ttl is bound at startup; restart postern to apply"),
			slog.Duration("running", baseline.Proxy.CacheTTL),
			slog.Duration("on_disk", reloaded.Proxy.CacheTTL),
		)
	}
	if reloaded.Proxy.Listen != "" && reloaded.Proxy.Listen != baseline.Proxy.Listen {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.listen"),
			slog.String("reason", "listener address is bound at startup; restart postern to apply"),
		)
	}
	if reloaded.Proxy.OnNoMatch != "" && reloaded.Proxy.OnNoMatch != baseline.Proxy.OnNoMatch {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.on_no_match"),
			slog.String("reason", "on_no_match is bound at startup; restart postern to apply"),
		)
	}
	if !credStoresEqual(reloaded.CredStores, baseline.CredStores) {
		logger.Warn("config edit ignored",
			slog.String("field", "credstores"),
			slog.String("reason", "credstore provider/token sources are resolved at startup; restart postern to apply"),
		)
	}
}

// credStoresEqual reports whether two credstore lists are semantically
// the same. The comparison is order-insensitive: a cosmetic reorder of
// `credstores:` entries in YAML is a no-op as far as the runtime is
// concerned, and firing a restart warning on cosmetic edits trains
// operators to ignore drift warnings. Equality requires identical Name +
// Provider + Token + Settings tuples — any of those changing is the drift
// the warning is meant to surface (Settings is bound into the resolver at
// boot, so an edit needs a restart). A per-field compare is used because
// CredStore is not comparable: Settings is a map.
func credStoresEqual(a, b []config.CredStore) bool {
	if len(a) != len(b) {
		return false
	}
	aSorted := slices.Clone(a)
	bSorted := slices.Clone(b)
	byName := func(x, y config.CredStore) int {
		switch {
		case x.Name < y.Name:
			return -1
		case x.Name > y.Name:
			return 1
		default:
			return 0
		}
	}
	slices.SortFunc(aSorted, byName)
	slices.SortFunc(bSorted, byName)
	return slices.EqualFunc(aSorted, bSorted, func(x, y config.CredStore) bool {
		return x.Name == y.Name &&
			x.Provider == y.Provider &&
			x.Token == y.Token &&
			maps.Equal(x.Settings, y.Settings)
	})
}

func countFatal(lints []config.LintError) int {
	var n int
	for _, l := range lints {
		if l.Severity == config.SeverityError {
			n++
		}
	}
	return n
}

func lintStrings(lints []config.LintError) []string {
	out := make([]string, 0, len(lints))
	for _, l := range lints {
		out = append(out, l.Error())
	}
	return out
}
