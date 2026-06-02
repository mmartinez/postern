package broker_test

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/mmartinez/postern/internal/broker"
)

func TestEngine_MatchReturnsFirstMatchingRule(t *testing.T) {
	t.Parallel()

	rules := []broker.Rule{
		{Host: "*.googleapis.com"},
		{Host: "api.anthropic.com"},
		{Host: "translate.googleapis.com"},
	}
	e := broker.NewEngine(rules)

	got, ok := e.Match("translate.googleapis.com")
	if !ok {
		t.Fatalf("Match: ok = false, want true")
	}
	if got.Host != "*.googleapis.com" {
		t.Fatalf("first match: got %q, want %q (ruleset order wins)", got.Host, "*.googleapis.com")
	}
}

func TestEngine_MatchUnknownHostReturnsFalse(t *testing.T) {
	t.Parallel()

	e := broker.NewEngine([]broker.Rule{
		{Host: "api.anthropic.com"},
	})

	if _, ok := e.Match("api.openai.com"); ok {
		t.Fatalf("Match unknown host: ok = true, want false")
	}
}

func TestEngine_NoRulesReturnsFalse(t *testing.T) {
	t.Parallel()

	e := broker.NewEngine(nil)
	if _, ok := e.Match("any.host"); ok {
		t.Fatalf("Match on empty engine: ok = true, want false")
	}
}

// TestEngine_SwapIsAtomicUnderConcurrentMatch hammers the engine with
// readers while a writer flips the ruleset. The race detector will catch
// torn reads or a missing memory barrier; the assertion is that every
// returned Rule came from *some* ruleset (never a synthesized half-rule).
func TestEngine_SwapIsAtomicUnderConcurrentMatch(t *testing.T) {
	t.Parallel()

	const (
		readers    = 8
		iterations = 5000
	)

	e := broker.NewEngine([]broker.Rule{
		{Host: "api.v1.test"},
	})

	var stop atomic.Bool
	var wg sync.WaitGroup

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if r, ok := e.Match("api.v1.test"); ok {
					if r.Host != "api.v1.test" && r.Host != "api.v2.test" {
						t.Errorf("torn read: matched rule has unexpected host %q", r.Host)
						return
					}
				} else if r, ok := e.Match("api.v2.test"); ok {
					if r.Host != "api.v2.test" {
						t.Errorf("torn read on v2: matched rule has host %q", r.Host)
						return
					}
				}
			}
		}()
	}

	for i := 0; i < iterations; i++ {
		if i%2 == 0 {
			e.Swap([]broker.Rule{{Host: "api.v2.test"}})
		} else {
			e.Swap([]broker.Rule{{Host: "api.v1.test"}})
		}
	}
	stop.Store(true)
	wg.Wait()
}

func TestEngine_SwapReplacesRules(t *testing.T) {
	t.Parallel()

	e := broker.NewEngine([]broker.Rule{{Host: "api.old.com"}})
	e.Swap([]broker.Rule{{Host: "api.new.com"}})

	if _, ok := e.Match("api.old.com"); ok {
		t.Fatalf("Match on superseded host: ok = true, want false")
	}
	if _, ok := e.Match("api.new.com"); !ok {
		t.Fatalf("Match on newly-swapped host: ok = false, want true")
	}
}

// TestEngine_SwapDoesNotMutateCallerSlice protects against an internal
// retention bug — the caller must be free to mutate the slice they passed
// in without affecting the engine.
func TestEngine_SwapDoesNotMutateCallerSlice(t *testing.T) {
	t.Parallel()

	rules := []broker.Rule{{Host: "api.example.com"}}
	e := broker.NewEngine(rules)
	rules[0].Host = "evil.example.com"

	got, ok := e.Match("api.example.com")
	if !ok {
		t.Fatalf("Match: ok = false, want true (engine retained mutated caller slice)")
	}
	if got.Host != "api.example.com" {
		t.Fatalf("engine kept caller mutation: got %q, want %q", got.Host, "api.example.com")
	}
}
