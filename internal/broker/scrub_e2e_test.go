package broker_test

import (
	"bufio"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/proxy"
)

// e2eCredential is the value the fake resolver hands the broker. Every test
// here asserts it never appears in anything the agent or the log stream sees.
const e2eCredential = "sk-ant-api03-ECHOED-BACK"

// echoingRule brokers every request to upstream's host with a single bearer
// header, the shape an API-key or token rule uses.
func echoingRule(t *testing.T, upstream *httptest.Server) broker.Rule {
	t.Helper()
	return broker.Rule{
		Host:      mustHost(t, upstream.URL),
		SecretRef: "op://V/I/f",
		Injection: broker.InjectSpec{
			Type:     broker.InjectHeader,
			Name:     "authorization",
			Template: "Bearer {{ CREDENTIAL }}",
		},
	}
}

// scrubProxy builds a real proxy fronted by a real broker hook, writing every
// log record to logs. scrub is the proxy.Config knob under test; pass nil for
// the default, which is on.
func scrubProxy(t *testing.T, upstream *httptest.Server, scrub *bool, logs *syncBuffer) *http.Client {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	engine := broker.NewEngine([]broker.Rule{echoingRule(t, upstream)})
	hook := broker.Hook(engine, &fakeResolver{value: e2eCredential}, config.OnNoMatchPassthrough, 0, true, logger) //nolint:bodyclose // closure; broker owns any synthetic body

	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:                 root,
		Minter:             fixtureMinter(t, root),
		Logger:             logger,
		UpstreamTLS:        upstreamTLS(t, upstream),
		PreUpstreamHandler: hook,
		ScrubResponses:     scrub,
	})
	require.NoError(t, err)

	return clientThroughProxy(t, startProxy(t, p), root)
}

// TestE2E_ReflectedCredentialNeverReachesTheAgent is the core P1 guarantee: an
// upstream that reflects the injected credential back, in a header and in a
// body, cannot deliver it to the agent.
func TestE2E_ReflectedCredentialNeverReachesTheAgent(t *testing.T) {
	t.Parallel()

	logs := &syncBuffer{}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+e2eCredential, r.Header.Get("Authorization"),
			"the upstream must have received the real credential to reflect it")
		w.Header().Set("Set-Cookie", "session="+e2eCredential+"; Path=/")
		w.Header().Set("X-Debug-Token", "prefix-"+e2eCredential+"-suffix")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"token":"`+e2eCredential+`","nested":{"again":"`+e2eCredential+`"}}`)
	}))
	t.Cleanup(upstream.Close)

	client := scrubProxy(t, upstream, nil, logs)

	resp := getThroughProxy(t, client, upstream.URL+"/v1/models")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body := readRespBody(t, resp)
	require.NotContains(t, body, e2eCredential, "the reflected credential reached the agent in the body")
	require.Contains(t, body, `"token":"<redacted>"`, "the body keeps its shape around the redaction")
	require.Empty(t, resp.Header.Get("Set-Cookie"), "a Set-Cookie echoing the credential must not reach the agent")
	for _, v := range resp.Header.Values("Set-Cookie") {
		require.NotContains(t, v, e2eCredential)
	}
	require.Empty(t, resp.Header.Get("X-Debug-Token"))
	require.NotContains(t, logs.String(), e2eCredential, "the credential reached the log stream")
}

// TestE2E_ReflectedCredentialAcrossUpstreamFlushes is the end-to-end form of
// the read-boundary case: the upstream writes the credential across two
// flushes, so the transport is free to deliver them as separate reads. The
// unit test in internal/proxy constructs every split offset explicitly; this
// one pins the property on a real TLS hop.
func TestE2E_ReflectedCredentialAcrossUpstreamFlushes(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok, "the fake upstream must support Flush")
		_, _ = io.WriteString(w, "prefix sk-an")
		flusher.Flush()
		_, _ = io.WriteString(w, "t-api03-ECHOED-BACK suffix")
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)

	client := scrubProxy(t, upstream, nil, &syncBuffer{})

	resp := getThroughProxy(t, client, upstream.URL+"/v1/models")
	defer func() { _ = resp.Body.Close() }()

	body := readRespBody(t, resp)
	require.NotContains(t, body, e2eCredential)
	require.Contains(t, body, "prefix ")
	require.Contains(t, body, " suffix")
}

// TestE2E_SSEStaysIncrementalWithScrubbingOn is the streaming guarantee. The
// upstream holds the connection open after the first event, so if the scrubber
// buffered the body the client could not read that first event until the
// upstream finished — which it never does until the test releases it.
func TestE2E_SSEStaysIncrementalWithScrubbingOn(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	// The upstream handler blocks on <-release, so it must be released on every
	// exit path. A failed require calls FailNow -> runtime.Goexit, which skips
	// the rest of this function; without the cleanup the handler never returns
	// and upstream.Close blocks until the binary times out, turning a clean
	// assertion failure into a hung run.
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		flusher, ok := w.(http.Flusher)
		require.True(t, ok, "the fake upstream must support Flush")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		_, _ = io.WriteString(w, "data: token="+e2eCredential+"\n\n")
		flusher.Flush()
		// The upstream is deliberately unfinished until the test releases it.
		<-release
		_, _ = io.WriteString(w, "data: second\n\n")
		flusher.Flush()
	}))
	t.Cleanup(upstream.Close)
	// Registered after upstream.Close so it runs FIRST: t.Cleanup is LIFO, and
	// Close blocks until every handler returns, so the release has to precede it.
	t.Cleanup(unblock)

	client := scrubProxy(t, upstream, nil, &syncBuffer{})

	resp := getThroughProxy(t, client, upstream.URL+"/sse")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// One reader for the whole body. A bufio.Reader may pull more than the
	// first line out of resp.Body, so reading resp.Body directly afterwards
	// would strand whatever it buffered and block until the test timeout.
	rd := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		line, err := rd.ReadString('\n')
		if err != nil {
			first <- ""
			return
		}
		first <- line
	}()

	select {
	case got := <-first:
		require.NotContains(t, got, e2eCredential, "the SSE event carried the credential")
		require.Contains(t, got, "data: token=")
		unblock()
	case <-time.After(10 * time.Second):
		unblock()
		t.Fatal("the first SSE event never arrived while the upstream was still writing: the body was buffered")
	}

	rest, err := io.ReadAll(rd)
	require.NoError(t, err)
	require.Contains(t, string(rest), "data: second")
}

// TestE2E_UnbrokeredResponseIsForwardedUnchanged is the zero-work path on a
// real hop: with no broker hook at all, nothing is injected, so the response
// arrives byte-for-byte.
func TestE2E_UnbrokeredResponseIsForwardedUnchanged(t *testing.T) {
	t.Parallel()

	payload := `{"ok":true,"padding":"` + strings.Repeat("x", 4096) + `"}`
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Untouched", "yes")
		_, _ = io.WriteString(w, payload)
	}))
	t.Cleanup(upstream.Close)

	logs := &syncBuffer{}
	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      fixtureMinter(t, root),
		Logger:      slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		UpstreamTLS: upstreamTLS(t, upstream),
	})
	require.NoError(t, err)

	resp := getThroughProxy(t, clientThroughProxy(t, startProxy(t, p), root), upstream.URL+"/plain")
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, payload, readRespBody(t, resp))
	require.Equal(t, "yes", resp.Header.Get("X-Untouched"))
	require.NotContains(t, logs.String(), e2eCredential)
}

// TestE2E_ScrubOptOutForwardsCredential is the escape hatch: an operator who
// explicitly turns the scrub off gets verbatim upstream behaviour. It exists so
// the knob's effect is pinned in both directions.
func TestE2E_ScrubOptOutForwardsCredential(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "reflected:"+e2eCredential)
	}))
	t.Cleanup(upstream.Close)

	off := false
	client := scrubProxy(t, upstream, &off, &syncBuffer{})

	resp := getThroughProxy(t, client, upstream.URL+"/v1/models")
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, "reflected:"+e2eCredential, readRespBody(t, resp),
		"with the scrub disabled the upstream response must reach the agent verbatim")
}

// mustHost extracts the bare hostname from an httptest server URL, which is
// the form broker rules match on.
func mustHost(t *testing.T, rawURL string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, http.NoBody)
	require.NoError(t, err)
	return req.URL.Hostname()
}

func getThroughProxy(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, http.NoBody)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// readRespBody drains a response body. It is spelled differently from the
// package's readBody, which drains a request body for injection assertions.
func readRespBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(b)
}
