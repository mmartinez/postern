package runtime_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/runtime"
	"github.com/stretchr/testify/require"
)

// tunnelFixture is a plain TCP upstream for raw-CONNECT tests: stall holds
// the accepted conn forever, echo bounces bytes back, halfClose writes a
// payload and then half-closes to exercise CloseWrite forwarding.
type tunnelFixture struct {
	ln     net.Listener
	addr   string
	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

func newTunnelUpstream(t *testing.T, mode string) *tunnelFixture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &tunnelFixture{ln: ln, addr: ln.Addr().String()}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			if f.closed {
				f.mu.Unlock()
				_ = c.Close()
				continue
			}
			f.conns = append(f.conns, c)
			f.mu.Unlock()
			switch mode {
			case "echo":
				go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
			case "halfClose":
				_, _ = c.Write([]byte("payload"))
				if tc, ok := c.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			case "stall":
				// Hold the conn without writing anything.
			}
		}
	}()
	t.Cleanup(func() {
		f.mu.Lock()
		f.closed = true
		for _, c := range f.conns {
			_ = c.Close()
		}
		f.mu.Unlock()
		_ = ln.Close()
	})
	return f
}

// bufferedConn pairs the raw conn with a reader that may hold buffered
// tunnel bytes past the CONNECT response.
type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (b bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// dialTunnel opens a raw CONNECT tunnel through the proxy at addr and
// returns the client-side conn positioned just past the 200 response.
func dialTunnel(t *testing.T, addr, hostport string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	_, err = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", hostport, hostport)
	require.NoError(t, err)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect}) //nolint:bodyclose // a 200 CONNECT response has no body; the conn IS the tunnel
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return bufferedConn{Conn: c, r: br}
}

// newLifecycleRuntime builds a runtime for lifecycle tests. mutate runs
// before New; when it leaves CA unset a fresh fixture CA is generated and
// returned so tests can trust it in their clients.
func newLifecycleRuntime(t *testing.T, mutate func(*runtime.Options)) (*runtime.Runtime, *ca.CA, *strings.Builder) {
	t.Helper()
	var logs strings.Builder
	opts := runtime.Options{
		Addr:   "127.0.0.1:0",
		Logger: slog.New(slog.NewTextHandler(&logs, nil)),
		// Raw tunnels only: every host declines interception so CONNECT
		// exercises goproxy's OkConnect relay path.
		ShouldIntercept: func(string) bool { return false },
	}
	if mutate != nil {
		mutate(&opts)
	}
	if opts.CA == nil {
		opts.CA = fixtureCA(t)
	}
	rt, err := runtime.New(opts)
	require.NoError(t, err)
	return rt, opts.CA, &logs
}

func startRuntime(t *testing.T, rt *runtime.Runtime) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("runtime did not shut down within 5s of cancel")
		}
	})
	return cancel
}

func TestTunnel_HalfCloseForwardedThroughTracking(t *testing.T) {
	t.Parallel()
	up := newTunnelUpstream(t, "halfClose")
	rt, _, _ := newLifecycleRuntime(t, nil)
	startRuntime(t, rt)

	client := dialTunnel(t, rt.Addr(), up.addr)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(client)
	require.NoError(t, err)
	require.Equal(t, "payload", string(got), "client must see the payload then a clean EOF, not a hang")
}

func TestStalledHandshakeReaped(t *testing.T) {
	t.Parallel()
	rt, _, _ := newLifecycleRuntime(t, func(o *runtime.Options) {
		o.TestStalledConnTimeout = 300 * time.Millisecond
		o.TestReapInterval = 50 * time.Millisecond
	})
	startRuntime(t, rt)

	// Open a TCP conn and send nothing post-accept: a stalled handshake.
	c, err := net.DialTimeout("tcp", rt.Addr(), 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	start := time.Now()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 16)
	_, err = c.Read(buf)
	require.Error(t, err, "server must close the silent conn")
	require.Less(t, time.Since(start), 4*time.Second, "close must happen near the tier-1 threshold, not the read deadline")
}

func TestIdleTunnelReapedAndGoroutinesSettle(t *testing.T) {
	up := newTunnelUpstream(t, "stall")
	rt, _, _ := newLifecycleRuntime(t, func(o *runtime.Options) {
		o.TestTunnelIdleTimeout = 200 * time.Millisecond
		o.TestReapInterval = 50 * time.Millisecond
	})
	startRuntime(t, rt)

	// Baseline taken with the runtime's own goroutines (serve, reaper) and
	// the upstream accept loop already live.
	before := goruntime.NumGoroutine()
	client := dialTunnel(t, rt.Addr(), up.addr)
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 16)
	_, err := client.Read(buf)
	require.Error(t, err, "stalled tunnel must be closed within the tier-2 bound")

	require.Eventually(t, func() bool {
		return goruntime.NumGoroutine() <= before+2
	}, 3*time.Second, 50*time.Millisecond, "relay goroutines must return to baseline after reap")
}

func TestSSEStreamSurvivesIdleReap(t *testing.T) {
	t.Parallel()
	// TLS upstream streaming an event every 50ms for ~1.2s total.
	srv := newStreamingTLSUpstream(t, 50*time.Millisecond, 24)
	rt, root, _ := newLifecycleRuntime(t, func(o *runtime.Options) {
		o.ShouldIntercept = nil // MITM everything
		o.UpstreamTLS = srv.TLSConfig()
		o.TestTunnelIdleTimeout = 200 * time.Millisecond
		o.TestReapInterval = 50 * time.Millisecond
	})
	startRuntime(t, rt)

	proxyURL, _ := url.Parse("http://" + rt.Addr())
	caPool := x509.NewCertPool()
	caPool.AddCert(root.Cert)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
		},
	}

	resp, err := client.Get(srv.URL())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read events well past one tier-2 threshold period (200ms): activity
	// from the stream's writes must keep resetting the reap timer.
	start := time.Now()
	events := make(chan string, 64)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "data:") {
				events <- line
			}
		}
		readErr <- sc.Err()
	}()

	lastAt := start
	count := 0
	for count < 12 {
		select {
		case <-events:
			count++
			lastAt = time.Now()
		case err := <-readErr:
			require.GreaterOrEqual(t, count, 12, "stream truncated before exceeding the idle threshold")
			require.NoError(t, err)
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("stream stalled after %d events; reap killed a live SSE stream", count)
		}
	}
	// The 12th event arrives at ~600ms, six threshold periods in: activity
	// demonstrably resets the timer instead of a fixed deadline cutting us.
	require.Greater(t, lastAt.Sub(start), 400*time.Millisecond)
	// Drain the rest without error to prove the stream stayed healthy.
	remaining := 24 - count
	for i := 0; i < remaining; i++ {
		select {
		case <-events:
		case err := <-readErr:
			require.NoError(t, err)
			t.Fatalf("stream errored early at event %d", count+i)
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for remaining stream events")
		}
	}
}

func TestShutdownDrainsThenForceClosesTunnels(t *testing.T) {
	t.Parallel()
	up := newTunnelUpstream(t, "echo")
	rt, _, logs := newLifecycleRuntime(t, func(o *runtime.Options) {
		o.TestShutdownBudget = 600 * time.Millisecond
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))

	client := dialTunnel(t, rt.Addr(), up.addr)
	ping := func() error {
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := client.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		_, err := io.ReadFull(client, buf)
		if err == nil && string(buf) != "ping" {
			err = fmt.Errorf("echo mismatch: %q", buf)
		}
		return err
	}
	require.NoError(t, ping())

	cancel()

	// Run must NOT return while the drain window is open, and the live
	// tunnel must still pass bytes during it.
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("Run returned %v before the shutdown budget expired", err)
	default:
	}
	require.NoError(t, ping(), "tunnel must keep passing bytes during the drain window")

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the shutdown budget expired")
	}
	out := logs.String()
	require.Contains(t, out, "shutdown drain complete")
	require.Contains(t, out, "force_closed=1", "the live tunnel must be force-closed at budget expiry")
}

func newStreamingTLSUpstream(t *testing.T, every time.Duration, total int) *upstreamFixture {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < total; i++ {
			if _, err := fmt.Fprintf(w, "event: tick\ndata: %d\n\n", i); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(every)
		}
	}))
	t.Cleanup(srv.Close)
	return &upstreamFixture{srv: srv}
}
