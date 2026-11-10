package proxy_test

import (
	"bytes"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
	"github.com/mmartinez/postern/internal/proxy"
)

func TestProxyAuthenticationBeforeAllExecution(t *testing.T) {
	t.Parallel()
	key, verifier, err := identity.Generate()
	require.NoError(t, err)
	e := broker.NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: verifier}}))
	var hooks, upstream atomic.Int32
	u := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		require.Zero(t, len(r.Header.Values("Proxy-Authorization")), "proxy credentials were not stripped")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer u.Close()
	root := fixtureCA(t)
	var logs bytes.Buffer
	p, err := proxy.New(proxy.Config{
		CA: root, Minter: fixtureMinter(t, root), Authenticator: e,
		Logger: slog.New(slog.NewJSONHandler(&logs, nil)),
		PreUpstreamHandler: func(r *http.Request) *http.Response {
			hooks.Add(1)
			require.Zero(t, len(r.Header.Values("Proxy-Authorization")), "proxy credentials were not stripped")
			require.Equal(t, "agent", identity.FromContext(r.Context()).Name())
			return nil
		},
	})
	require.NoError(t, err)
	valid := "Basic " + base64.StdEncoding.EncodeToString([]byte("agent:"+key))
	for _, method := range []string{http.MethodGet, http.MethodConnect} {
		for _, headers := range [][]string{nil, {"Bearer " + key}, {"Basic invalid"}, {valid, valid}, {strings.Repeat("a", 4096)}} {
			r := httptest.NewRequest(method, u.URL+"/?key="+key, nil)
			for _, h := range headers {
				r.Header.Add("Proxy-Authorization", h)
			}
			w := httptest.NewRecorder()
			p.Handler().ServeHTTP(w, r)
			require.Equal(t, http.StatusProxyAuthRequired, w.Code)
			require.Equal(t, `Basic realm="postern"`, w.Header().Get("Proxy-Authenticate"))
			require.False(t, strings.Contains(w.Body.String(), key), "response exposed proxy key")
		}
	}
	require.Zero(t, hooks.Load())
	require.Zero(t, upstream.Load())
	r := httptest.NewRequest(http.MethodGet, u.URL, nil)
	r.Header.Set("Proxy-Authorization", valid)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.EqualValues(t, 1, hooks.Load())
	require.EqualValues(t, 1, upstream.Load())
	require.True(t, strings.Contains(logs.String(), `"agent":"agent"`), "validated agent missing from logs")
	require.False(t, strings.Contains(logs.String(), key), "log exposed proxy key")
	require.False(t, strings.Contains(logs.String(), verifier), "log exposed verifier")
}

func TestAuthenticatedResponseScrubsCredentialEcho(t *testing.T) {
	t.Parallel()
	key, verifier, err := identity.Generate()
	require.NoError(t, err)
	secret, _, err := identity.Generate()
	require.NoError(t, err)
	engine := broker.NewEngine(nil)
	require.NoError(t, engine.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: verifier}}))
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("compressed") {
			w.Header().Set("Content-Encoding", "br")
		}
		_, _ = io.WriteString(w, secret)
	}))
	defer upstream.Close()
	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA: root, Minter: fixtureMinter(t, root), Authenticator: engine,
		PreUpstreamHandler: func(r *http.Request) *http.Response {
			*r = *r.WithContext(broker.WithInjectedCredentials(r.Context(), secret))
			return nil
		},
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:"+key)))
	recorder := httptest.NewRecorder()
	p.Handler().ServeHTTP(recorder, req)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.False(t, strings.Contains(recorder.Body.String(), secret), "response exposed injected credential")
	require.Contains(t, recorder.Body.String(), "<redacted>")
	req = httptest.NewRequest(http.MethodGet, upstream.URL+"?compressed", nil)
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:"+key)))
	recorder = httptest.NewRecorder()
	p.Handler().ServeHTTP(recorder, req)
	require.Equal(t, http.StatusBadGateway, recorder.Code)
	require.False(t, strings.Contains(recorder.Body.String(), secret), "compressed response exposed injected credential")
}

func TestEnrollmentProbeRequiresAuthenticationAndBypassesRouting(t *testing.T) {
	t.Parallel()
	key, verifier, err := identity.Generate()
	require.NoError(t, err)
	engine := broker.NewEngine(nil)
	require.NoError(t, engine.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: verifier}}))
	root := fixtureCA(t)
	var hooks atomic.Int32
	p, err := proxy.New(proxy.Config{
		CA: root, Minter: fixtureMinter(t, root), Authenticator: engine,
		PreUpstreamHandler: func(_ *http.Request) *http.Response { hooks.Add(1); return nil },
	})
	require.NoError(t, err)
	for _, authenticated := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodOptions, "/.well-known/postern/client-auth", nil)
		if authenticated {
			req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:"+key)))
		}
		recorder := httptest.NewRecorder()
		p.Handler().ServeHTTP(recorder, req)
		expected := http.StatusProxyAuthRequired
		if authenticated {
			expected = http.StatusNoContent
		}
		require.Equal(t, expected, recorder.Code)
	}
	require.Zero(t, hooks.Load())
}
