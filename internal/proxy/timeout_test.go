package proxy_test

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/proxy"
)

// TestProxy_StalledUpstream_FailsWithinBound pins the response-header
// timeout: an upstream that accepts TCP but never responds must not pin a
// proxy goroutine and file descriptor forever. With a short injected
// timeout the client's request fails within the bound and the goroutine
// count returns to baseline once everything is torn down.
func TestProxy_StalledUpstream_FailsWithinBound(t *testing.T) {
	t.Parallel()

	baseline := runtime.NumGoroutine()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Block until the client (here: the proxy) goes away — the stalled
		// upstream of the bug report, minus the forever.
		<-r.Context().Done()
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:                        root,
		Minter:                    fixtureMinter(t, root),
		Logger:                    slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:               upstreamTLS(t, upstream),
		TestResponseHeaderTimeout: 250 * time.Millisecond,
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	start := time.Now()
	resp, err := client.Get(upstream.URL + "/stall")
	elapsed := time.Since(start)
	require.Error(t, err, "stalled upstream must fail, not hang")
	require.Less(t, elapsed, 2*time.Second,
		"request took %v — response-header timeout not in effect", elapsed)
	if resp != nil {
		_ = resp.Body.Close()
	}

	// The bound is only useful if it releases resources: after the failure
	// and teardown, goroutines must drain back to baseline.
	t.Cleanup(func() {
		require.Eventually(t, func() bool {
			return runtime.NumGoroutine() <= baseline+5
		}, 5*time.Second, 100*time.Millisecond,
			"goroutines did not return to baseline (%d now vs %d before) — stalled-upstream goroutine leaked",
			runtime.NumGoroutine(), baseline)
	})
}

// TestProxy_TunnelDial_FailsWithinBound_ConstantBody pins both halves of
// the tunnel-dial fix: the CONNECT dial for a tunneled (non-brokered) host
// is bounded by Tr.DialContext, and the resulting 502 carries the constant
// anti-oracle body instead of the raw dial error.
func TestProxy_TunnelDial_FailsWithinBound_ConstantBody(t *testing.T) {
	t.Parallel()

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:              root,
		Minter:          fixtureMinter(t, root),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		ShouldIntercept: func(string) bool { return false }, // tunnel everything
		TestDialTimeout: 250 * time.Millisecond,
	})
	require.NoError(t, err)
	proxyAddr := strings.TrimPrefix(startProxy(t, p), "http://")

	// RFC 5737 TEST-NET-1: guaranteed non-routable. Networks that reject it
	// immediately (EHOSTUNREACH/ENETUNREACH) still exercise the sanitized
	// 502; networks that blackhole it exercise the dial timeout.
	const blackhole = "192.0.2.1:81"

	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	start := time.Now()
	_, err = fmtFprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", blackhole, blackhole)
	require.NoError(t, err)

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	require.NoError(t, err, "no reply from proxy within read deadline")
	require.Contains(t, status, "502 Bad Gateway",
		"tunnel dial failure must surface as 502, got %q", status)
	require.Less(t, time.Since(start), 3*time.Second,
		"CONNECT to non-routable address took %v — tunnel dial is unbounded", time.Since(start))

	body, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.NotContains(t, string(body), "192.0.2.1")
	require.NotContains(t, string(body), "timeout")
	require.NotContains(t, string(body), "unreachable")
	require.NotContains(t, string(body), "refused")
}

// fmtFprintf writes formatted bytes to conn with a deadline so a broken
// proxy fails the test instead of hanging it.
func fmtFprintf(conn net.Conn, format string, args ...any) (int, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return fmt.Fprintf(conn, format, args...)
}
