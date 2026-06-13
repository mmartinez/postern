package oauth2

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

// TestIntegration_OAuth2BearerInjectedFromLiveExchange exercises the whole
// Slice 1 path with real components: the broker hook matches the host, calls the
// real oauth2 resolver, which performs a live client_credentials exchange against
// a fake TLS IdP, and the rendered "Bearer <token>" lands on the request the
// upstream receives. Only the IdP and upstream are fakes.
func TestIntegration_OAuth2BearerInjectedFromLiveExchange(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		require.Equal(t, "Bearer tok-1", r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	res, err := providerFor(idp).NewResolver(context.Background(), "csecret", ccSettings(idp.srv.URL))
	require.NoError(t, err)

	engine := broker.NewEngine([]broker.Rule{{
		Host:      mustHost(t, upstream.URL),
		SecretRef: "oauth2://corp",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "authorization",
			Template: "Bearer {{ CREDENTIAL }}",
		},
	}})
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, discardLog()) //nolint:bodyclose // returns nil on success

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	require.Nil(t, hook(req), "a healthy exchange must not short-circuit the request") //nolint:bodyclose // nil on success
	require.Equal(t, "Bearer tok-1", req.Header.Get("Authorization"))

	resp, err := upstream.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), upstreamHits.Load())
}

// TestIntegration_OAuth2FailsClosedOnTokenEndpointError verifies the fail-closed
// invariant: when the token endpoint errors, the hook returns 502, injects
// nothing, and the upstream is never contacted.
func TestIntegration_OAuth2FailsClosedOnTokenEndpointError(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	idp.status = http.StatusInternalServerError

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamHits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	res, err := providerFor(idp).NewResolver(context.Background(), "csecret", ccSettings(idp.srv.URL))
	require.NoError(t, err)

	engine := broker.NewEngine([]broker.Rule{{
		Host:      mustHost(t, upstream.URL),
		SecretRef: "oauth2://corp",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
	}})
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, discardLog()) //nolint:bodyclose // closure

	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	require.NoError(t, err)
	resp := hook(req)
	require.NotNil(t, resp, "a failed exchange must short-circuit with a synthetic response")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Empty(t, req.Header.Get("Authorization"), "no token must be injected on failure")
	require.Equal(t, int64(0), upstreamHits.Load(), "upstream must not be contacted on token-endpoint failure (fail closed)")
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Hostname()
}
