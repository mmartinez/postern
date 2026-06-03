package broker_test

import (
	"encoding/json"
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
	"github.com/mmartinez/postern/internal/proxy"
)

// surfaceProxy stands up the full MITM path (CA + minter + goproxy + broker
// hook + fake resolver) against upstream, returning a client that talks
// through the proxy. maxBodyBytes is the global body cap passed to the hook.
func surfaceProxy(t *testing.T, upstream *httptest.Server, rule broker.Rule, value string, maxBodyBytes int) (*http.Client, *fakeResolver) {
	t.Helper()
	root := fixtureCA(t)
	minter := fixtureMinter(t, root)
	res := &fakeResolver{value: value}
	hook := broker.Hook(broker.NewEngine([]broker.Rule{rule}), res, config.OnNoMatchPassthrough, maxBodyBytes, slog.New(slog.NewTextHandler(io.Discard, nil))) //nolint:bodyclose // synthetic body; goproxy closes it after writing to the client

	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             minter,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)
	return clientThroughProxy(t, startProxy(t, p), root), res
}

func surfaceRule(surfaces ...broker.Surface) broker.Rule {
	return broker.Rule{
		Host:      "127.0.0.1",
		SecretRef: "op://Agents/X/api_key",
		Injection: broker.InjectSpec{
			Type:     broker.InjectPlaceholder,
			Name:     "__tok__",
			Template: "{{ CREDENTIAL }}",
			Surfaces: surfaces,
		},
	}
}

// E2E: a placeholder in a JSON body arrives at the upstream JSON-escaped. The
// resolver value carries a double quote, so a raw splice would corrupt the
// JSON; correct escaping makes it decode back to the original value.
func TestE2E_BodySubstitution_JSONEscaped(t *testing.T) {
	t.Parallel()

	const value = `sk"x`
	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(req.Body)
		var got map[string]string
		require.NoError(t, json.Unmarshal(body, &got), "upstream body must be valid JSON")
		require.Equal(t, value, got["api_key"], "JSON-escaped placeholder must decode to the resolved value")
	}))
	t.Cleanup(upstream.Close)

	client, res := surfaceProxy(t, upstream, surfaceRule(broker.SurfaceBody), value, 1<<20)
	resp, err := client.Post(upstream.URL+"/v1/x", "application/json", strings.NewReader(`{"api_key":"__tok__"}`))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), hits.Load())
	require.Equal(t, int64(1), res.calls.Load())
}

// E2E: a placeholder in the URL path arrives path-escaped. The value contains a
// slash, which must reach the upstream as %2F (one segment), not a raw "/".
func TestE2E_PathSubstitution_PathEscaped(t *testing.T) {
	t.Parallel()

	const value = "a/b"
	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		require.Contains(t, req.RequestURI, "/v1/a%2Fb/models", "path value must arrive percent-escaped")
	}))
	t.Cleanup(upstream.Close)

	client, _ := surfaceProxy(t, upstream, surfaceRule(broker.SurfacePath), value, 1<<20)
	resp, err := client.Get(upstream.URL + "/v1/__tok__/models")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), hits.Load())
}

// E2E: a placeholder in the query string arrives query-escaped. The value
// contains a space and an ampersand; correct escaping keeps it a single param.
func TestE2E_QuerySubstitution_QueryEscaped(t *testing.T) {
	t.Parallel()

	const value = "a b&c"
	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		require.Equal(t, value, req.URL.Query().Get("key"), "query value must round-trip through escaping")
	}))
	t.Cleanup(upstream.Close)

	client, _ := surfaceProxy(t, upstream, surfaceRule(broker.SurfaceQuery), value, 1<<20)
	resp, err := client.Get(upstream.URL + "/v1/models?key=__tok__")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), hits.Load())
}

// E2E: a body over the cap is rejected with 413 and the upstream is never
// contacted (and the resolver is never called).
func TestE2E_BodyOverCap_413_UpstreamNotContacted(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	client, res := surfaceProxy(t, upstream, surfaceRule(broker.SurfaceBody), "sk-real", 16)
	resp, err := client.Post(upstream.URL+"/v1/x", "application/json", strings.NewReader(strings.Repeat("x", 256)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	require.Zero(t, hits.Load(), "upstream must not be contacted for an oversized body")
	require.Zero(t, res.calls.Load(), "resolver must not be called for an oversized body")
}

// E2E: a compressed body (Content-Encoding set) is forwarded byte-for-byte; the
// proxy cannot text-substitute into opaque compressed bytes.
func TestE2E_CompressedBody_ForwardedUnmodified(t *testing.T) {
	t.Parallel()

	const sent = `{"api_key":"__tok__"}`
	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(req.Body)
		require.Equal(t, sent, string(body), "compressed body must be forwarded unmodified")
	}))
	t.Cleanup(upstream.Close)

	client, _ := surfaceProxy(t, upstream, surfaceRule(broker.SurfaceBody), "sk-real", 1<<20)
	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/v1/x", strings.NewReader(sent))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip") // not really gzip; postern must not touch it
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), hits.Load())
}

// E2E: a multipart body is forwarded byte-for-byte.
func TestE2E_MultipartBody_ForwardedUnmodified(t *testing.T) {
	t.Parallel()

	const sent = "--x\r\nContent-Disposition: form-data; name=\"k\"\r\n\r\n__tok__\r\n--x--\r\n"
	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(req.Body)
		require.Equal(t, sent, string(body), "multipart body must be forwarded unmodified")
	}))
	t.Cleanup(upstream.Close)

	client, _ := surfaceProxy(t, upstream, surfaceRule(broker.SurfaceBody), "sk-real", 1<<20)
	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/v1/x", strings.NewReader(sent))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), hits.Load())
}
