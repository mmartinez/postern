package runtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

// TestNew_ServerIdleTimeoutDefault pins the inbound server's IdleTimeout:
// without it net/http never reaps silent keep-alive connections (ReadTimeout
// is deliberately unset so streaming responses are never cut), and idle
// agent connections accumulate goroutines forever.
func TestNew_ServerIdleTimeoutDefault(t *testing.T) {
	t.Parallel()

	root, err := ca.Generate(time.Now())
	require.NoError(t, err)
	rt, err := New(Options{CA: root, Addr: "127.0.0.1:0"})
	require.NoError(t, err)

	require.Equal(t, 120*time.Second, rt.srv.IdleTimeout)
	// Streaming guard: Read/WriteTimeout must stay zero or SSE responses
	// would be cut mid-stream (docs/architecture.md promises incremental
	// delivery).
	require.Zero(t, rt.srv.ReadTimeout)
	require.Zero(t, rt.srv.WriteTimeout)
}
