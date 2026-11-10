package broker

import (
	"sync"
	"sync/atomic"

	"github.com/mmartinez/postern/internal/identity"
)

// Engine holds the active ruleset and serves first-match lookups. The
// ruleset is loaded atomically so the proxy's hot path can call Match
// concurrently with the config watcher swapping in a new ruleset.
type Engine struct {
	snapshot atomic.Pointer[engineSnapshot]
	mu       sync.Mutex
	work     map[*activeWork]struct{}
}

type enrolledAgent struct {
	verifier  identity.Verifier
	principal *identity.Principal
}

type authorizationEpoch [1]byte

type engineSnapshot struct {
	epoch  *authorizationEpoch
	rules  []Rule
	agents map[string]enrolledAgent
}

// NewEngine constructs an Engine with the given ruleset. The slice is
// copied so subsequent caller mutations do not leak into the engine.
func NewEngine(rules []Rule) *Engine {
	e := &Engine{work: make(map[*activeWork]struct{})}
	e.Swap(rules)
	return e
}

// Match returns the first rule whose host pattern matches host, in the
// order the rules were supplied. The bool is false when no rule matches.
// Engines must be obtained from NewEngine; the zero value is not usable.
func (e *Engine) Match(host string) (Rule, bool) {
	// Index rather than range-by-value: Rule is large enough that copying it
	// per iteration trips gocritic's rangeValCopy.
	rules := e.snapshot.Load().rules
	for i := range rules {
		if rules[i].Match(host) {
			return rules[i], true
		}
	}
	return Rule{}, false
}

// Swap atomically replaces the active ruleset. The new slice is copied so
// later caller mutations cannot affect dispatch. Concurrent Match calls
// observe either the previous or the new ruleset, never a torn read.
func (e *Engine) Swap(rules []Rule) {
	cp := append([]Rule(nil), rules...)
	e.mu.Lock()
	defer e.mu.Unlock()
	agents := make(map[string]enrolledAgent)
	if previous := e.snapshot.Load(); previous != nil {
		agents = previous.agents
	}
	e.snapshot.Store(&engineSnapshot{rules: cp, agents: agents, epoch: &authorizationEpoch{}})
}

// Len reports how many rules the active ruleset holds. The reloader reads it
// to refuse a swap that would empty a working ruleset.
func (e *Engine) Len() int {
	return len(e.snapshot.Load().rules)
}
