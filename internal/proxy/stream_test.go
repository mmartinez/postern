package proxy_test

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/proxy"
)

// TestProxy_StreamingNotBuffered proves that an SSE-style upstream — chunks
// written with deliberate gaps between them — survives the proxy round-trip
// with timing largely intact. The acceptance bar is "chunks arrive
// incrementally with a 100ms tolerance"; we measure the gap between
// chunk receipts on the client and require it to be at least 60% of the
// upstream's pause. A buffering proxy would deliver everything in one read
// at the end and fail the per-chunk timing assertion.
func TestProxy_StreamingNotBuffered(t *testing.T) {
	t.Parallel()

	const (
		chunks      = 3
		upstreamGap = 200 * time.Millisecond
		minGap      = 120 * time.Millisecond // 60% of upstreamGap, absorbs jitter
	)

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		require.True(t, ok, "test setup: upstream ResponseWriter must support Flusher")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		for i := 0; i < chunks; i++ {
			_, _ = fmt.Fprintf(w, "data: chunk-%d\n\n", i)
			flusher.Flush()
			// Deliberate exception to the no-sleep-in-tests rule: this sleep
			// is the fake upstream's emission cadence, not a wait on the system
			// under test. The assertion below proves the proxy preserves the
			// gap (doesn't buffer), which requires a real inter-chunk delay.
			time.Sleep(upstreamGap)
		}
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      fixtureMinter(t, root),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS: upstreamTLS(t, upstream),
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/sse", http.NoBody)
	require.NoError(t, err)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	reader := bufio.NewReader(resp.Body)
	arrivals := make([]time.Time, 0, chunks)
	start := time.Now()
	for len(arrivals) < chunks {
		// Read until a blank line — each SSE event ends with \n\n.
		line, err := reader.ReadString('\n')
		require.NoError(t, err)
		if line == "\n" || line == "\r\n" {
			arrivals = append(arrivals, time.Now())
		}
	}
	total := time.Since(start)

	// Chunks must not all land in the same 100ms window — that's the
	// hallmark of a buffering proxy.
	for i := 1; i < len(arrivals); i++ {
		gap := arrivals[i].Sub(arrivals[i-1])
		require.GreaterOrEqual(t, gap, minGap,
			"chunk %d arrived only %v after chunk %d — proxy appears to be buffering", i, gap, i-1)
	}

	// Total time should be in the same order of magnitude as
	// (chunks-1) * upstreamGap. A buffering proxy would either match this
	// (because it can't avoid the upstream gap) or, in the worst case, hold
	// chunks longer. Use a generous upper bound to avoid CI flakiness.
	require.LessOrEqual(t, total, time.Duration(chunks+2)*upstreamGap,
		"streaming SSE took %v — significantly longer than the upstream gap budget", total)
}
