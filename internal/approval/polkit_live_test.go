//go:build linux

package approval

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
)

// TestPolkitLive drives the real polkit dialog. It needs the policy from
// `postern approval policy` installed, an authentication agent running, and
// a person at the desktop to answer three dialogs.
func TestPolkitLive(t *testing.T) {
	if os.Getenv("POSTERN_POLKIT_E2E") != "1" {
		t.Skip("set POSTERN_POLKIT_E2E=1 to answer real approval dialogs")
	}
	a := NewPolkit()

	t.Log("dialog 1: authenticate to approve")
	got, err := a.Approve(t.Context(), "run live test 1 of 3: approve this")
	require.NoError(t, err)
	require.Equal(t, broker.OutcomeApproved, got)

	t.Log("dialog 2: press Cancel")
	got, err = a.Approve(t.Context(), "run live test 2 of 3: press Cancel")
	require.NoError(t, err)
	require.Equal(t, broker.OutcomeDismissed, got)

	t.Log("dialog 3: do not answer; it must close by itself after 10 seconds")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	got, err = a.Approve(ctx, "run live test 3 of 3: leave this open")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, broker.OutcomeUnavailable, got)
}
