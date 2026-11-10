package broker

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

type identityApprover struct{ calls atomic.Int32 }

func (a *identityApprover) Approve(_ context.Context, reason string) (Outcome, error) {
	a.calls.Add(1)
	if !strings.Contains(reason, "agent Alice") && !strings.Contains(reason, "agent Bob") {
		return OutcomeDenied, nil
	}
	return OutcomeApproved, nil
}

func TestApprovalGrantsAreIsolatedByIdentityIncarnation(t *testing.T) {
	t.Parallel()
	a := &identityApprover{}
	g := NewGate(t.Context(), GateConfig{Approver: a})
	rule := Rule{Host: "example.test", Approval: &config.Approval{TTL: time.Hour}}
	alice := identity.NewPrincipal("Alice")
	for _, p := range []*identity.Principal{alice, alice, identity.NewPrincipal("Bob"), identity.NewPrincipal("Alice")} {
		r := httptest.NewRequest("GET", "https://example.test/", nil)
		r = r.WithContext(identity.WithPrincipal(r.Context(), p))
		require.True(t, g.allow(r, rule, "", "test://ref"))
	}
	require.EqualValues(t, 3, a.calls.Load())
}

type heldIdentityApprover struct {
	opened  chan string
	release chan struct{}
}

func (a *heldIdentityApprover) Approve(ctx context.Context, reason string) (Outcome, error) {
	a.opened <- reason
	select {
	case <-a.release:
		return OutcomeApproved, nil
	case <-ctx.Done():
		return OutcomeUnavailable, ctx.Err()
	}
}

func TestApprovalFlightsAreIsolatedBetweenAgents(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a := &heldIdentityApprover{opened: make(chan string, 2), release: make(chan struct{}, 2)}
	g := NewGate(ctx, GateConfig{Approver: a})
	rule := Rule{Host: "example.test", Approval: &config.Approval{TTL: time.Hour}}
	finished := make(chan bool, 2)
	start := func(name string) {
		r := httptest.NewRequest("GET", "https://example.test/", nil)
		r = r.WithContext(identity.WithPrincipal(ctx, identity.NewPrincipal(name)))
		go func() { finished <- g.allow(r, rule, "", "test://ref") }()
	}
	start("Alice")
	select {
	case reason := <-a.opened:
		require.True(t, strings.Contains(reason, "agent Alice"))
	case <-time.After(time.Second):
		t.Fatal("first approval did not open")
	}
	start("Bob")
	a.release <- struct{}{}
	select {
	case reason := <-a.opened:
		require.True(t, strings.Contains(reason, "agent Bob"))
	case <-time.After(time.Second):
		t.Fatal("another identity reused the first approval flight")
	}
	a.release <- struct{}{}
	for range 2 {
		select {
		case allowed := <-finished:
			require.True(t, allowed)
		case <-time.After(time.Second):
			t.Fatal("approval did not finish")
		}
	}
}
