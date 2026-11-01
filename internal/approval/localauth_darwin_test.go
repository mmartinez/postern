//go:build darwin && cgo

package approval

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
)

func TestLAOutcome(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		code int
		want broker.Outcome
	}{
		{name: "authentication failed", code: laAuthenticationFailed, want: broker.OutcomeDenied},
		{name: "user cancel", code: laUserCancel, want: broker.OutcomeDismissed},
		{name: "system cancel", code: laSystemCancel, want: broker.OutcomeDismissed},
		{name: "app cancel", code: laAppCancel, want: broker.OutcomeDismissed},
		{name: "any other code", code: 1, want: broker.OutcomeUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, laOutcome(tc.code))
		})
	}
}

// TestLocalAuth_CanceledContext drives the real framework with a context
// that is already done: the evaluation is invalidated before anyone can
// answer it, and Approve still waits for the reply before returning.
func TestLocalAuth_CanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	got, err := New().Approve(ctx, "run a test that is cancelled before it asks")
	require.Equal(t, broker.OutcomeUnavailable, got)
	require.ErrorIs(t, err, context.Canceled)
}
