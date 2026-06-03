package proxy_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/proxy"
)

// countingResolver is a broker.Resolver that records how many times it was
// asked to resolve, so a test can assert the transport guard fired before
// any credential lookup happened.
type countingResolver struct{ calls *atomic.Int64 }

func (c countingResolver) Resolve(_ context.Context, _, _ string) (string, error) {
	c.calls.Add(1)
	return "sk-should-never-be-used", nil
}

// TestProxy_PlainHTTPMatch_FailsClosed_UpstreamNotContacted is the
// end-to-end counterpart to broker's TestHook_PlainHTTPMatchFailsClosed: a
// real plaintext request routed through the proxy for a host that matches a
// broker rule must surface 502 with neither the credential resolver nor the
// upstream contacted. Plain http through a forward proxy keeps
// req.URL.Scheme == "http" (goproxy only rewrites to https after it
// terminates TLS during MITM), so the guard denies injecting a secret onto
// a cleartext hop.
func TestProxy_PlainHTTPMatch_FailsClosed_UpstreamNotContacted(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "should never be reached")
	}))
	t.Cleanup(upstream.Close)

	upURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	var resolverCalls atomic.Int64
	rule := broker.Rule{
		Host:      upURL.Hostname(),
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "x-api-key", Template: "{{ CREDENTIAL }}"},
	}
	hook := broker.Hook( //nolint:bodyclose // hook is a closure; broker owns the synthetic body
		broker.NewEngine([]broker.Rule{rule}),
		countingResolver{&resolverCalls},
		config.OnNoMatchPassthrough,
		0,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             fixtureMinter(t, root),
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)

	pu, err := url.Parse(proxyURL)
	require.NoError(t, err)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(upstream.URL)
	require.NoError(t, err, "client should receive a response, not a TCP drop")
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode,
		"plain-http matched rule must surface as 502")
	require.Zero(t, upstreamHits.Load(),
		"CRITICAL: upstream contacted for a plain-http matched rule — fail-closed invariant violated")
	require.Zero(t, resolverCalls.Load(),
		"resolver called before the transport check — credential lookup must not happen over cleartext")
}
