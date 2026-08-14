package broker_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/proxy"
)

// TestE2E_BrokerInjectsHeaderThroughMITMProxy exercises the full broker path:
// real goproxy + real local CA + real broker.Hook + fake resolver + real
// httptest.NewTLSServer. The upstream asserts that the injected header
// arrives with the resolver-supplied value, and the client (talking to
// the proxy) gets a clean 200. The acceptance walkthrough reuses this
// integration against the live Anthropic endpoint.
func TestE2E_BrokerInjectsHeaderThroughMITMProxy(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamHits.Add(1)
		if got := req.Header.Get("x-api-key"); got != "sk-from-resolver" {
			t.Errorf("upstream saw x-api-key=%q, want %q", got, "sk-from-resolver")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	minter := fixtureMinter(t, root)

	// httptest binds 127.0.0.1; the proxy sees that IP as the request host,
	// not the cert's "example.com" SAN, so the broker rule must match the
	// real destination the proxy receives.
	engine := broker.NewEngine([]broker.Rule{{
		Host:      "127.0.0.1",
		SecretRef: "op://Agents/Anthropic/api_key",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}})
	res := &fakeResolver{value: "sk-from-resolver"}
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body; goproxy closes it after writing to the client

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             minter,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)

	client := clientThroughProxy(t, startProxy(t, p), root)
	resp, err := client.Get(upstream.URL) // upstream cert SAN is example.com; SNI override in upstreamTLS makes the proxy dial succeed
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), upstreamHits.Load())
	require.Equal(t, int64(1), res.calls.Load())
}

// TestE2E_BrokerInjectsMultipleHeadersThroughMITMProxy is the multi-header
// counterpart: one rule, one secret_ref, two headers. The upstream asserts both
// arrive with the resolver-supplied value, and the resolver counter proves the
// secret was read exactly once for the request — the whole point of feeding both
// headers from one rule instead of two.
func TestE2E_BrokerInjectsMultipleHeadersThroughMITMProxy(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamHits.Add(1)
		if got := req.Header.Get("authorization"); got != "Bearer sk-from-resolver" {
			t.Errorf("upstream saw authorization=%q, want %q", got, "Bearer sk-from-resolver")
		}
		if got := req.Header.Get("x-api-key"); got != "sk-from-resolver" {
			t.Errorf("upstream saw x-api-key=%q, want %q", got, "sk-from-resolver")
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	minter := fixtureMinter(t, root)

	engine := broker.NewEngine([]broker.Rule{{
		Host:      "127.0.0.1",
		SecretRef: "op://Agents/example/api_key",
		Injections: []broker.InjectSpec{
			{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
			{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
		},
	}})
	res := &fakeResolver{value: "sk-from-resolver"}
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body; goproxy closes it after writing to the client

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             minter,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)

	client := clientThroughProxy(t, startProxy(t, p), root)
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), upstreamHits.Load())
	require.Equal(t, int64(1), res.calls.Load(), "one secret_ref must be resolved once, however many headers it feeds")
}

// TestE2E_ResolverErrorReturns502_UpstreamNotContacted verifies the
// fail-closed invariant: on resolver error the proxy returns 502 *and*
// the upstream counter stays at zero. A regression
// here would mean a credential failure could silently degrade to an
// unauthenticated upstream call.
func TestE2E_ResolverErrorReturns502_UpstreamNotContacted(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	minter := fixtureMinter(t, root)

	// httptest binds 127.0.0.1; the proxy sees that IP as the request host,
	// not the cert's "example.com" SAN, so the broker rule must match the
	// real destination the proxy receives.
	engine := broker.NewEngine([]broker.Rule{{
		Host:      "127.0.0.1",
		SecretRef: "op://Agents/Anthropic/api_key",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}})
	res := &fakeResolver{err: errors.New("token revoked")}
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body; goproxy closes it after writing to the client

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             minter,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)

	client := clientThroughProxy(t, startProxy(t, p), root)
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Equal(t, int64(0), upstreamHits.Load(), "upstream must not be contacted on resolver failure (fail closed)")
}

// TestE2E_OnNoMatchBlock_UpstreamNotContacted verifies the allowlist-only
// containment proxy.on_no_match: block promises: a request whose host
// matches no rule gets a 502 and the upstream counter stays at zero. The
// rule here deliberately targets a different host than the upstream so the
// request falls through to the block branch.
func TestE2E_OnNoMatchBlock_UpstreamNotContacted(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	minter := fixtureMinter(t, root)

	// The proxy sees the upstream as 127.0.0.1; this rule matches a
	// different host, so the request is unmatched and block must deny it.
	engine := broker.NewEngine([]broker.Rule{{
		Host:      "api.anthropic.com",
		SecretRef: "op://Agents/Anthropic/api_key",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "x-api-key",
			Template: "{{ CREDENTIAL }}",
		},
	}})
	res := &fakeResolver{value: "sk-from-resolver"}
	hook := broker.Hook(engine, res, config.OnNoMatchBlock, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body; goproxy closes it after writing to the client

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             minter,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)

	client := clientThroughProxy(t, startProxy(t, p), root)
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Equal(t, int64(0), upstreamHits.Load(), "upstream must not be contacted on no-match under block")
	require.Equal(t, int64(0), res.calls.Load(), "resolver must not be called on no-match under block")
}

// TestE2E_BrokerSignsOAuth1ThroughMITMProxy exercises the OAuth 1.0a signing
// path end to end: real goproxy + CA + broker.Hook resolve the four credential
// refs (fake resolver) and sign the request, and the upstream confirms it
// received a well-formed "Authorization: OAuth ..." header.
func TestE2E_BrokerSignsOAuth1ThroughMITMProxy(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		upstreamHits.Add(1)
		// Assert in-handler (not via a shared variable) to stay race-free.
		auth := req.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "OAuth ") || !strings.Contains(auth, "oauth_signature=") {
			t.Errorf("upstream Authorization = %q, want an OAuth 1.0a signature", auth)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	minter := fixtureMinter(t, root)

	engine := broker.NewEngine([]broker.Rule{{
		Host: "127.0.0.1",
		Injection: broker.InjectSpec{
			Type: broker.InjectOAuth1,
			OAuth1: broker.OAuth1Refs{
				ConsumerKeyRef:    "op://v/ck",
				ConsumerSecretRef: "op://v/cs",
				TokenRef:          "op://v/tk",
				TokenSecretRef:    "op://v/ts",
			},
		},
	}})
	res := &fakeResolver{value: "secret-val"}
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body; goproxy closes it after writing to the client

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             minter,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)

	client := clientThroughProxy(t, startProxy(t, p), root)
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), upstreamHits.Load())
}

// Fixture helpers below mirror the patterns used in
// internal/proxy/proxy_test.go (kept local rather than exported to avoid
// growing the proxy package's public surface for test plumbing).

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

// upstreamTLS trusts the httptest server's self-signed cert and pins SNI
// to "example.com" since the test cert has no IP SAN — the proxy dials by
// IP and the handshake would otherwise fail.
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

func clientThroughProxy(t *testing.T, proxyURL string, root *ca.CA) *http.Client {
	t.Helper()
	u, err := url.Parse(proxyURL)
	require.NoError(t, err)

	caPool := x509.NewCertPool()
	caPool.AddCert(root.Cert)

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

func startProxy(t *testing.T, p *proxy.Proxy) string {
	t.Helper()
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return srv.URL
}

// Compile-time check: fakeResolver (defined in hook_test.go) satisfies
// broker.Resolver. A rename of the interface would surface here at build
// time rather than as a runtime panic deep in the integration test.
var _ broker.Resolver = (*fakeResolver)(nil)
