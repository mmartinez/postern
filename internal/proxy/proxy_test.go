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

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/proxy"
)

// fixtureCA + fixtureMinter mint a fresh local CA for each test.
func fixtureCA(t *testing.T) *ca.CA {
	t.Helper()
	c, err := ca.Generate(time.Now())
	require.NoError(t, err)
	return c
}

func fixtureMinter(t *testing.T, root *ca.CA) *ca.Minter {
	t.Helper()
	m, err := ca.NewMinter(root, 32, time.Now)
	require.NoError(t, err)
	return m
}

// upstreamTLS returns a tls.Config the proxy's outbound transport can use
// against an httptest.NewTLSServer. We trust the server's own cert as a root
// and override ServerName because httptest's testcert is issued for
// "example.com" with no 127.0.0.1 IP SAN — the proxy dials by IP so without
// an SNI override the handshake would fail. Production uses system trust
// against real-DNS upstreams where neither hack is needed.
func upstreamTLS(t *testing.T, srv *httptest.Server) *tls.Config {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return &tls.Config{
		RootCAs:    pool,
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	}
}

// clientThroughProxy returns an http.Client that routes HTTPS via proxyURL
// and trusts the proxy's CA so MITM leaves verify.
func clientThroughProxy(t *testing.T, proxyURL string, ca *ca.CA) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: 5 * time.Second,
	}
}

// startProxy spins the postern proxy up on a random localhost port and
// returns the proxy URL plus a cleanup hook.
func startProxy(t *testing.T, p *proxy.Proxy) string {
	t.Helper()
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProxy_CONNECT_MITM_TrustChain(t *testing.T) {
	t.Parallel()

	// Upstream serves a known body.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello from upstream")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	minter := fixtureMinter(t, root)

	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      minter,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS: upstreamTLS(t, upstream),
	})
	require.NoError(t, err)

	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "hello from upstream", string(body))
}

// With UpstreamTLS nil (the production path — postern dials real-DNS
// upstreams with system trust), the proxy must verify the upstream's
// certificate. An untrusted upstream cert must be rejected, never
// transparently re-encrypted with the credential already injected. This pins
// the invariant so a change to goproxy's default transport (its
// InsecureSkipVerify) can't silently turn postern into a credential-leaking
// open proxy without a test going red.
func TestProxy_NilUpstreamTLS_RejectsUntrustedUpstream(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "should never be reached over an unverified connection")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:     root,
		Minter: fixtureMinter(t, root),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		// UpstreamTLS deliberately nil — exercise the production system-trust path.
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	resp, err := client.Get(upstream.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		require.NotEqual(t, http.StatusOK, resp.StatusCode,
			"untrusted upstream cert must not yield a 200 through the proxy")
	}
	require.Zero(t, upstreamHits.Load(),
		"CRITICAL: upstream reached over an unverified TLS connection")
}

func TestNew_RequiresCAAndMinter(t *testing.T) {
	t.Parallel()
	_, err := proxy.New(proxy.Config{})
	require.Error(t, err)

	root := fixtureCA(t)
	_, err = proxy.New(proxy.Config{CA: root})
	require.Error(t, err)
}
