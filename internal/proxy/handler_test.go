package proxy_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/proxy"
)

// captureUpstream records the first request that reaches the upstream so
// tests can assert what passed through unchanged.
type captureUpstream struct {
	mu      atomic.Pointer[capturedRequest]
	handler http.Handler
}

type capturedRequest struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

func (c *captureUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Store(&capturedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Header: r.Header.Clone(),
		Body:   body,
	})
	c.handler.ServeHTTP(w, r)
}

func TestProxy_Passthrough_RequestReachesUpstreamUnchanged(t *testing.T) {
	t.Parallel()

	cap := &captureUpstream{handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Server", "postern-upstream-test")
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "brewed")
	})}
	upstream := httptest.NewTLSServer(cap)
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      fixtureMinter(t, root),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		UpstreamTLS: upstreamTLS(t, upstream),
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	req, err := http.NewRequest(http.MethodPost, upstream.URL+"/echo", strings.NewReader(`{"hello":"world"}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Trace-Id", "abc-123")

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusTeapot, resp.StatusCode)
	require.Equal(t, "brewed", string(body))
	require.Equal(t, "postern-upstream-test", resp.Header.Get("X-Server"))

	rec := cap.mu.Load()
	require.NotNil(t, rec, "upstream must have received the request")
	require.Equal(t, http.MethodPost, rec.Method)
	require.Equal(t, "/echo", rec.Path)
	require.Equal(t, "application/json", rec.Header.Get("Content-Type"))
	require.Equal(t, "abc-123", rec.Header.Get("X-Trace-Id"))
	require.Equal(t, `{"hello":"world"}`, string(rec.Body))
}

func TestProxy_LogsRedactSensitiveHeaders(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      fixtureMinter(t, root),
		Logger:      logger,
		UpstreamTLS: upstreamTLS(t, upstream),
	})
	require.NoError(t, err)
	proxyURL := startProxy(t, p)
	client := clientThroughProxy(t, proxyURL, root)

	const secret = "sk-live-DO-NOT-LEAK-THIS-1234567890"
	req, err := http.NewRequest(http.MethodGet, upstream.URL+"/secret", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Api-Key", secret)
	req.Header.Set("Cookie", "session="+secret)

	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Give the response handler a brief window to flush its log line.
	time.Sleep(20 * time.Millisecond)

	got := logBuf.String()
	require.NotEmpty(t, got, "proxy should log the request")
	require.False(t, strings.Contains(got, secret),
		"CRITICAL: proxy log must redact sensitive header values; got:\n%s", got)
	require.Contains(t, got, "/secret", "log should still reference the path")
}

// Compile-time check we're using tls.Config so the import isn't elided after
// refactors that move the TLS plumbing around.
var _ = tls.VersionTLS12
