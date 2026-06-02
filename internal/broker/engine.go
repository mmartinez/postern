package broker

import "sync/atomic"

// Engine holds the active ruleset and serves first-match lookups. The
// ruleset is loaded atomically so the proxy's hot path can call Match
// concurrently with the config watcher swapping in a new ruleset.
type Engine struct {
	rules atomic.Pointer[[]Rule]
}

// NewEngine constructs an Engine with the given ruleset. The slice is
// copied so subsequent caller mutations do not leak into the engine.
func NewEngine(rules []Rule) *Engine {
	e := &Engine{}
	e.Swap(rules)
	return e
}

// Match returns the first rule whose host pattern matches host, in the
// order the rules were supplied. The bool is false when no rule matches.
// Engines must be obtained from NewEngine; the zero value is not usable.
func (e *Engine) Match(host string) (Rule, bool) {
	for _, r := range *e.rules.Load() {
		if r.Match(host) {
			return r, true
		}
	}
	return Rule{}, false
}

// Swap atomically replaces the active ruleset. The new slice is copied so
// later caller mutations cannot affect dispatch. Concurrent Match calls
// observe either the previous or the new ruleset, never a torn read.
func (e *Engine) Swap(rules []Rule) {
	cp := append([]Rule(nil), rules...)
	e.rules.Store(&cp)
}
