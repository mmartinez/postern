package broker_test

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/proxy"
)

// TestRedTeam_NoPlaceholderTemplate_FailsClosed is the regression for the
// fail-open defect: a rule whose template omits {{ CREDENTIAL }} used to pass
// validation (warning only), boot, resolve the secret, and then forward a
// credential-less request to the upstream while logging success. It must now
// fail closed at two layers.
func TestRedTeam_NoPlaceholderTemplate_FailsClosed(t *testing.T) {
	t.Parallel()

	// Layer 1 — config validation rejects it as a FATAL lint, so the proxy
	// never boots (or hot-reloads) into the fail-open state.
	lints := config.Validate(&config.Config{
		Proxy:      config.Proxy{Listen: "127.0.0.1:1701", CacheTTL: 1, OnNoMatch: config.OnNoMatchPassthrough},
		CredStores: []config.CredStore{{Name: "d", Provider: "test-provider"}},
		Rules: []config.Rule{{
			Host:      "127.0.0.1",
			SecretRef: "op://V/I/f",
			Inject:    config.Inject{Type: config.InjectTypeHeader, Name: "authorization", Template: "Bearer "},
		}},
	}, nil)
	var fatal int
	for _, l := range lints {
		if l.Severity == config.SeverityError {
			fatal++
		}
	}
	require.Positive(t, fatal, "placeholder-free template must be a fatal lint; lints=%v", lints)

	// Layer 2 — even if such a rule reaches the broker (a future caller, a
	// hot-reload edge), the broker backstop fails closed: 502, resolver value
	// discarded, upstream never contacted.
	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	engine := broker.NewEngine([]broker.Rule{{
		Host:      "127.0.0.1",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer "},
	}})
	res := &fakeResolver{value: "sk-the-real-secret"}
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             fixtureMinter(t, root),
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)

	client := clientThroughProxy(t, startProxy(t, p), root)
	resp, err := client.Get(upstream.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode, "must fail closed with 502")
	require.Zero(t, upstreamHits.Load(), "upstream must NOT be contacted for a placeholder-free template")
}

// TestRedTeam_EmptyResolvedCredential_FailsClosed covers the amplifier: a
// resolver that returns ("", nil) must not produce a credential-less injected
// request. The hook rejects an empty value before injecting.
func TestRedTeam_EmptyResolvedCredential_FailsClosed(t *testing.T) {
	t.Parallel()

	var upstreamHits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	engine := broker.NewEngine([]broker.Rule{{
		Host:      "127.0.0.1",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
	}})
	res := &fakeResolver{value: ""}                                                                                  // resolver returns empty, no error
	hook := broker.Hook(engine, res, config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             fixtureMinter(t, root),
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
	require.Zero(t, upstreamHits.Load(), "upstream must NOT be contacted when the resolved credential is empty")
}

// TestRedTeam_FailClosedBodyIsUniform pins the information-oracle fix: every
// fail-closed 502 the broker returns must carry the same generic body, so a
// hostile agent cannot distinguish a resolve failure from an inject failure
// from a transport refusal. The specific stage stays in the logs only.
func TestRedTeam_FailClosedBodyIsUniform(t *testing.T) {
	t.Parallel()

	read := func(resp *http.Response) string {
		t.Helper()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return string(b)
	}

	rule := broker.Rule{
		Host:      "api.example.com",
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "authorization", Template: "Bearer {{ CREDENTIAL }}"},
	}

	// Stage A: resolver error.
	hookResolveErr := broker.Hook(broker.NewEngine([]broker.Rule{rule}), //nolint:bodyclose // synthetic body
		&fakeResolver{err: errors.New("token revoked")},
		config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Stage B: insecure transport (plain http) for a matched host.
	hookTransport := broker.Hook(broker.NewEngine([]broker.Rule{rule}), //nolint:bodyclose // synthetic body
		&fakeResolver{value: "sk"},
		config.OnNoMatchPassthrough, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))

	reqHTTPS, _ := http.NewRequest(http.MethodGet, "https://api.example.com/v1", http.NoBody)
	reqHTTP, _ := http.NewRequest(http.MethodGet, "http://api.example.com/v1", http.NoBody)

	respA := hookResolveErr(reqHTTPS) //nolint:bodyclose // read() closes it; bodyclose can't trace through the helper
	respB := hookTransport(reqHTTP)   //nolint:bodyclose // read() closes it; bodyclose can't trace through the helper
	require.NotNil(t, respA)
	require.NotNil(t, respB)
	require.Equal(t, http.StatusBadGateway, respA.StatusCode)
	require.Equal(t, http.StatusBadGateway, respB.StatusCode)

	bodyA := read(respA)
	bodyB := read(respB)
	require.Equal(t, bodyA, bodyB, "fail-closed bodies must be identical across stages (no failure-stage oracle)")
	require.Equal(t, "postern: bad gateway\n", bodyA)
}
