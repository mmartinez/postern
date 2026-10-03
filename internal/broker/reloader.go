package broker

import (
	"context"
	"io"
	"log/slog"
	"maps"
	"slices"
	"sync/atomic"

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

// VersionCounter is the ruleset version source for the admin health
// endpoint (GET /healthz): construction of a ruleset counts as version 1,
// and every applied hot reload bumps the counter. It lives beside the
// reloader because the reloader is the sole writer — swaps happen only on
// its goroutine — while the admin handler reads it concurrently, which is
// why every access goes through the atomic.
type VersionCounter struct {
	v atomic.Uint64
}

// NewVersionCounter returns a counter seeded at 1: the engine was
// constructed with its boot ruleset, so a freshly started server already
// has a loaded ruleset to report.
func NewVersionCounter() *VersionCounter {
	c := &VersionCounter{}
	c.v.Store(1)
	return c
}

// Bump records one applied swap. Safe to call concurrently with Load; the
// reloader calls it from its own goroutine after engine.Swap succeeds.
func (c *VersionCounter) Bump() {
	if c == nil {
		return
	}
	c.v.Add(1)
}

// Load returns the current ruleset version. A nil counter reports 0,
// which callers surface as "no ruleset loaded" (brokerless passthrough).
func (c *VersionCounter) Load() uint64 {
	if c == nil {
		return 0
	}
	return c.v.Load()
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
// version optionally receives a Bump on every applied swap so the caller
// can expose a monotonically increasing ruleset version (the admin health
// endpoint's ruleset_version); passing no counter keeps the historical
// behavior unchanged, so existing callers compile and behave identically.
//
// RunReloader returns when ctx is cancelled or when events closes.
// Construct it in a dedicated goroutine after wiring the watcher; the
// CLI server command owns that orchestration.
func RunReloader(ctx context.Context, engine *Engine, events <-chan config.Event, logger *slog.Logger, baseline *Baseline, version ...*VersionCounter) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var vc *VersionCounter
	if len(version) > 0 {
		vc = version[0]
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			applyReload(engine, ev, logger, baseline, vc)
		}
	}
}

// applyReload is the per-event decision: swap on clean reload, log + skip
// on fatal lint, and surface warnings without blocking the swap. A nil
// version simply skips the bump.
func applyReload(engine *Engine, ev config.Event, logger *slog.Logger, baseline *Baseline, version *VersionCounter) {
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
	// Refuse to downgrade a working ruleset to nothing while the running
	// policy would fail open: with no rules every request matches nothing and
	// on_no_match: passthrough tunnels it untouched, so the proxy would keep
	// answering while silently injecting nothing. Under on_no_match: block the
	// same config is the opposite — zero rules is how a deny-all deployment
	// refuses everything — so that swap is allowed. on_no_match is bound at
	// startup, so the decision follows the policy in force, not the edit.
	if len(newRules) == 0 && engine.Len() > 0 && !denyAllAtBoot(baseline) {
		logger.Warn("config reload rejected",
			slog.String("reason", "new config has no rules and on_no_match is not block; the previous ruleset keeps serving"),
		)
		return
	}
	engine.Swap(newRules)
	version.Bump()
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

// denyAllAtBoot reports whether the policy in force refuses every unmatched
// request. Only the reloader needs it: an empty ruleset is a deny-all policy
// under on_no_match: block and a silent open relay under passthrough, so the
// empty-ruleset guard has to know which one the server started with. A nil
// baseline means nothing is known, which is treated as fail-open.
func denyAllAtBoot(baseline *Baseline) bool {
	return baseline != nil && baseline.Proxy.OnNoMatch == config.OnNoMatchBlock
}

// warnDriftedFields surfaces edits to proxy/token fields that the engine
// swap path does not pick up. Without this signal the user sees "config
// reload applied" and assumes their cache_ttl/token change took effect.
func warnDriftedFields(reloaded *config.Config, baseline Baseline, logger *slog.Logger) {
	if reloaded.Proxy.CacheTTL != baseline.Proxy.CacheTTL {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.cache_ttl"),
			slog.String("reason", "cache_ttl is bound at startup; restart postern to apply"),
			slog.Duration("on_disk", reloaded.Proxy.CacheTTL),
		)
	}
	if !cacheBlockEqual(reloaded.Proxy.Cache, baseline.Proxy.Cache) {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.cache"),
			slog.String("reason", "cache settings are bound at startup; restart postern to apply"),
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
	if reloaded.Proxy.MaxBodyBytes != baseline.Proxy.MaxBodyBytes {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.max_body_bytes"),
			slog.String("reason", "the proxy-wide body cap is bound at startup; restart postern to apply (per-rule inject.max_body_bytes hot-reloads)"),
		)
	}
	if !scrubResponsesEqual(reloaded.Proxy.ScrubResponses, baseline.Proxy.ScrubResponses) {
		logger.Warn("config edit ignored",
			slog.String("field", "proxy.scrub_responses"),
			slog.String("reason", "the response scrub is bound at startup; restart postern to apply"),
		)
	}
	if !credStoresEqual(reloaded.CredStores, baseline.CredStores) {
		logger.Warn("config edit ignored",
			slog.String("field", "credstores"),
			slog.String("reason", "credstore provider/token sources are resolved at startup; restart postern to apply"),
		)
	}
}

// cacheBlockEqual reports whether two optional proxy.cache blocks are
// equivalent. Cache is a struct of comparable durations, so a nil-aware value
// comparison suffices.
func cacheBlockEqual(a, b *config.Cache) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
	}
}

// scrubResponsesEqual reports whether two optional scrub_responses settings
// are equivalent. The field is a *bool so that "absent" (the default, scrub
// on) and "explicitly false" are distinguishable, which means pointer identity
// cannot answer this; a nil-aware value comparison can.
func scrubResponsesEqual(a, b *bool) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	default:
		return *a == *b
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
