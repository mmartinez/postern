package proxy_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/proxy"
)

// TestProxy_PanicReturns502_UpstreamNotContacted makes the fail-closed
// invariant executable: a panic anywhere in the postern hook chain
// must surface to the client as 502, and the upstream must never see the
// request. A passing test means an attacker can't trigger a fall-through to
// the unauthenticated upstream by inducing a panic in our middleware.
func TestProxy_PanicReturns502_UpstreamNotContacted(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		_, _ = io.WriteString(w, "should never be reached")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      fixtureMinter(t, root),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS: upstreamTLS(t, upstream),
		PreUpstreamHandler: func(_ *http.Request) *http.Response {
			panic("deliberate test panic in pre-upstream hook")
		},
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	resp, err := client.Get(upstream.URL + "/triggers-panic")
	require.NoError(t, err, "client should still receive a response, not a TCP drop")
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode,
		"panic must surface as 502; got %d", resp.StatusCode)
	require.Zero(t, upstreamHits.Load(),
		"CRITICAL: upstream was contacted despite hook panic — fail-closed invariant violated")
}
