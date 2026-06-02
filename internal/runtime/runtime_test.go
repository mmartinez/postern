package runtime_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/runtime"
)

// fixtureCA mints a CA in-memory; no disk persistence so tests parallelize.
func fixtureCA(t *testing.T) *ca.CA {
	t.Helper()
	c, err := ca.Generate(time.Now())
	require.NoError(t, err)
	return c
}

func TestRuntime_RunShutsDownWhenContextCancelled(t *testing.T) {
	t.Parallel()
	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{
		CA:     root,
		Addr:   "127.0.0.1:0", // OS-assigned port; production passes a real one
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()

	// Wait for the listener to come up before cancelling.
	require.NoError(t, waitForListening(rt, 2*time.Second))

	cancel()
	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown should not surface an error")
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return within 10s of context cancellation")
	}
}

func TestRuntime_RunErrorsOnBindFailure(t *testing.T) {
	t.Parallel()
	root := fixtureCA(t)

	// Occupy a loopback port so the bind below is guaranteed to fail with
	// "address already in use" on every platform. Binding a privileged port
	// (:1) is not a reliable failure: some sandboxes set
	// net.ipv4.ip_unprivileged_port_start=0, letting any user bind it — in
	// which case Run would serve forever and hang the test instead of erroring.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	rt, err := runtime.New(runtime.Options{
		CA:     root,
		Addr:   occupied.Addr().String(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	require.NoError(t, err)

	err = rt.Run(t.Context())
	require.Error(t, err, "binding an already-bound address should fail")
}

func TestNew_RejectsMissingFields(t *testing.T) {
	t.Parallel()
	root := fixtureCA(t)

	_, err := runtime.New(runtime.Options{})
	require.Error(t, err, "missing CA must error")

	_, err = runtime.New(runtime.Options{CA: root})
	require.Error(t, err, "missing addr must error")
}

func TestNew_NilLoggerDefaultsToDiscard(t *testing.T) {
	t.Parallel()
	root := fixtureCA(t)

	// A nil logger must not panic — runtime falls back to a discard
	// handler so headless invocations work without callers wiring slog.
	// Running briefly proves the discard writer is actually exercised
	// (the "proxy listening" line gets emitted at startup).
	rt, err := runtime.New(runtime.Options{CA: root, Addr: "127.0.0.1:0"})
	require.NoError(t, err)
	require.NotNil(t, rt)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	cancel()
	<-done
}

func TestRuntime_ProxyServesThroughListener(t *testing.T) {
	t.Parallel()
	upstream := newTLSUpstream(t)
	defer upstream.Close()

	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{
		CA:          root,
		Addr:        "127.0.0.1:0",
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS: upstream.TLSConfig(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))

	proxyURL, _ := url.Parse("http://" + rt.Addr())
	caPool := x509.NewCertPool()
	caPool.AddCert(root.Cert)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: caPool, MinVersion: tls.VersionTLS12},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(upstream.URL())
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	cancel()
	<-done
}

// waitForListening polls rt.Addr() until the listener returns a non-zero
// port. Used by tests that hand a "127.0.0.1:0" placeholder so they don't
// race the listener startup goroutine.
func waitForListening(rt *runtime.Runtime, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if addr := rt.Addr(); addr != "" {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return context.DeadlineExceeded
}
