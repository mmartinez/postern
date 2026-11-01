package broker

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewGate_WallClock covers the default clock. Cooldowns and the refusal
// budget must expire in wall time, which keeps running while the machine
// sleeps, as pam_faillock's window does. Go's monotonic reading stops during
// sleep on Linux.
func TestNewGate_WallClock(t *testing.T) {
	t.Parallel()

	now := NewGate(t.Context(), GateConfig{}).now()
	require.Equal(t, now.Round(0), now, "the default clock must carry no monotonic reading")
}
