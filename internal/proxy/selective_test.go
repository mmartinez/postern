package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/proxy"
)

// clientTrustingUpstreamOnly routes HTTPS through the proxy while trusting only
// the upstream's real certificate — NOT the postern CA. A tunneled CONNECT
// therefore succeeds (the client validates the genuine upstream cert), while an
// intercepted CONNECT fails (the client rejects postern's minted leaf). That
// asymmetry is what proves whether interception happened. ServerName is pinned
// to example.com because httptest's testcert carries no 127.0.0.1 IP SAN.
func clientTrustingUpstreamOnly(t *testing.T, proxyURL string, upstream *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "example.com",
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}
}

// A non-brokered host must be tunneled, not MITM'd: the client reaches the real
// upstream and validates the upstream's own certificate. The client trusts only
// the upstream cert (not the postern CA), so success here is positive proof
// that postern minted no leaf and terminated no TLS.
func TestProxy_SelectiveMITM_NonBrokeredHostIsTunneled(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "hello from real upstream")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:              root,
		Minter:          fixtureMinter(t, root),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		ShouldIntercept: func(string) bool { return false }, // nothing is brokered
	})
	require.NoError(t, err)

	proxyURL := startProxy(t, p)
	client := clientTrustingUpstreamOnly(t, proxyURL, upstream)

	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "hello from real upstream", string(body))
	require.Equal(t, int64(1), hits.Load())
}

// The mirror of the tunnel test: when the host IS brokered, postern terminates
// TLS with a leaf the upstream-only client does not trust, so the request
// fails before any upstream contact. This proves flipping ShouldIntercept
// actually flips TLS termination.
func TestProxy_SelectiveMITM_BrokeredHostIsIntercepted(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "should not be reached by an upstream-only client")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:              root,
		Minter:          fixtureMinter(t, root),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:     upstreamTLS(t, upstream),
		ShouldIntercept: func(string) bool { return true }, // every host brokered
	})
	require.NoError(t, err)

	proxyURL := startProxy(t, p)
	client := clientTrustingUpstreamOnly(t, proxyURL, upstream)

	resp, err := client.Get(upstream.URL)
	// An upstream-only client MUST get a TLS handshake error: postern terminated
	// the connection with a leaf signed by a CA the client does not trust.
	require.Error(t, err, "upstream-only client must reject postern's MITM leaf")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Zero(t, hits.Load(), "upstream must not be reached when the client rejects the MITM leaf")
}

// on_no_match: block, expressed at connect time: a non-brokered host with
// BlockNonBrokered set has its CONNECT rejected before any tunnel or MITM, so
// the upstream is never contacted (fail-closed invariant).
func TestProxy_SelectiveMITM_BlockRejectsNonBrokeredAtConnect(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "blocked host must never be reached")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:               root,
		Minter:           fixtureMinter(t, root),
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		ShouldIntercept:  func(string) bool { return false }, // not brokered
		BlockNonBrokered: true,
	})
	require.NoError(t, err)

	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	resp, err := client.Get(upstream.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		require.NotEqual(t, http.StatusOK, resp.StatusCode,
			"a blocked CONNECT must not yield a 200")
	}
	require.Zero(t, hits.Load(), "CRITICAL: blocked host was contacted upstream")
}
