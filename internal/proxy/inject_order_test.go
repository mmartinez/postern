package proxy_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/proxy"
)

// lockedBuffer is a concurrency-safe io.Writer for capturing slog output
// without racing the proxy's request/response logging goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestProxy_InjectedCredentialNeverLogged pins a load-bearing ordering
// invariant: the request-logging handler runs BEFORE the broker injection
// handler, so a credential the broker injects is never present when the
// request is logged. The injected header name is deliberately one that
// redaction would NOT catch (it matches none of the sensitive prefixes /
// suffixes), so if the ordering were ever flipped the secret would appear in
// the log verbatim and this test would fail.
func TestProxy_InjectedCredentialNeverLogged(t *testing.T) {
	t.Parallel()

	const secret = "sk-INJECTED-DO-NOT-LOG-0987654321"
	const injectHeader = "X-Custom-Auth" // not in any sensitive prefix/suffix family

	cap := &captureUpstream{handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	upstream := httptest.NewTLSServer(cap)
	t.Cleanup(upstream.Close)

	logBuf := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// A minimal broker-like hook that injects the secret into a custom header.
	hook := func(req *http.Request) *http.Response {
		req.Header.Set(injectHeader, secret)
		return nil
	}

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             fixtureMinter(t, root),
		Logger:             logger,
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
	})
	require.NoError(t, err)
	client := clientThroughProxy(t, startProxy(t, p), root)

	resp, err := client.Get(upstream.URL + "/v1/messages")
	require.NoError(t, err)
	_ = resp.Body.Close()

	// Injection must actually have happened (otherwise the test proves nothing).
	rec := cap.mu.Load()
	require.NotNil(t, rec, "upstream must have received the request")
	require.Equal(t, secret, rec.Header.Get(injectHeader), "broker hook must have injected the credential")

	// ...yet the secret must never appear in the request log line.
	got := logBuf.String()
	require.NotEmpty(t, got, "proxy should log the request")
	require.NotContains(t, got, secret,
		"CRITICAL: injected credential leaked into the log — request logging must run before injection")
}
