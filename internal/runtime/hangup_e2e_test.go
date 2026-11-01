package runtime_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/runtime"
)

const hangupBound = 500 * time.Millisecond

// parkedHook is a pre-upstream hook that holds each request with the hangup
// watch armed, the way the broker holds a request while it waits.
type parkedHook struct {
	done    <-chan struct{}
	entered chan string     // request path once the watch is armed
	release chan struct{}   // lets one parked request finish
	outcome chan hookResult // one per request, after the watch stopped
}

type hookResult struct {
	path       string
	signalled  bool
	watchFound bool
}

func newParkedHook(t *testing.T) *parkedHook {
	t.Helper()
	return &parkedHook{
		done:    t.Context().Done(),
		entered: make(chan string, 4),
		release: make(chan struct{}),
		outcome: make(chan hookResult, 4),
	}
}

func (h *parkedHook) serve(req *http.Request) *http.Response {
	watch := broker.HangupWatchFrom(req.Context())
	if watch == nil {
		h.outcome <- hookResult{path: req.URL.Path}
		return textResponse(req, http.StatusBadGateway, "no hangup watch\n")
	}
	gone := make(chan struct{})
	stop := watch(func() { close(gone) })
	h.entered <- req.URL.Path
	body, err := io.ReadAll(req.Body)
	if err == nil {
		select {
		case <-gone:
		case <-h.release:
		case <-h.done:
		}
	}
	stop()
	res := hookResult{path: req.URL.Path, watchFound: true}
	select {
	case <-gone:
		res.signalled = true
	default:
	}
	h.outcome <- res
	if err != nil {
		return textResponse(req, http.StatusBadGateway, "body read failed\n")
	}
	return textResponse(req, http.StatusOK, fmt.Sprintf("%s %s:%s", req.Method, req.URL.Path, body))
}

func textResponse(req *http.Request, code int, body string) *http.Response {
	return &http.Response{
		StatusCode:    code,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func startHangupRuntime(t *testing.T, hook *parkedHook) (string, *ca.CA) {
	t.Helper()
	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{
		CA:                 root,
		Addr:               "127.0.0.1:0",
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		PreUpstreamHandler: hook.serve,
	})
	require.NoError(t, err)
	startRuntime(t, rt)
	return rt.Addr(), root
}

// dialIntercepted opens a CONNECT tunnel and completes TLS against the
// postern-minted leaf. It returns the TLS conn and the raw TCP conn under it.
func dialIntercepted(t *testing.T, addr string, root *ca.CA) (*tls.Conn, *net.TCPConn) {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })
	_, err = io.WriteString(raw, "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n")
	require.NoError(t, err)
	// The proxy writes nothing past the 200 until the client speaks TLS, so
	// reading the response through a throwaway bufio.Reader loses no bytes.
	resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: http.MethodConnect}) //nolint:bodyclose // a 200 CONNECT response has no body
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	tc := tls.Client(raw, &tls.Config{ServerName: "example.test", RootCAs: pool, MinVersion: tls.VersionTLS12})
	require.NoError(t, tc.Handshake())
	return tc, raw.(*net.TCPConn)
}

func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func TestHangupWatchSignalsWhenClientLeaves(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		leave func(tc *tls.Conn, raw *net.TCPConn)
	}{
		{"tls close", func(tc *tls.Conn, _ *net.TCPConn) { _ = tc.Close() }},
		{"FIN without close_notify", func(_ *tls.Conn, raw *net.TCPConn) { _ = raw.Close() }},
		{"RST", func(_ *tls.Conn, raw *net.TCPConn) {
			_ = raw.SetLinger(0)
			_ = raw.Close()
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hook := newParkedHook(t)
			addr, root := startHangupRuntime(t, hook)
			conn, raw := dialIntercepted(t, addr, root)
			_, err := io.WriteString(conn, "GET /wait HTTP/1.1\r\nHost: example.test\r\n\r\n")
			require.NoError(t, err)
			select {
			case <-hook.entered:
			case res := <-hook.outcome:
				t.Fatalf("hook ran without an armed watch: %+v", res)
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for the hook")
			}

			tc.leave(conn, raw)
			select {
			case res := <-hook.outcome:
				require.True(t, res.signalled, "hook finished without a hangup signal")
			case <-time.After(hangupBound):
				t.Fatalf("no hangup signal within %v of the client leaving", hangupBound)
			}
		})
	}
}

func TestHangupWatchKeepsKeepAliveStreamIntact(t *testing.T) {
	t.Parallel()
	hook := newParkedHook(t)
	addr, root := startHangupRuntime(t, hook)
	conn, _ := dialIntercepted(t, addr, root)
	br := bufio.NewReader(conn)

	_, err := io.WriteString(conn, "POST /one HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\n")
	require.NoError(t, err)
	require.Equal(t, "/one", waitFor(t, hook.entered, "hook /one"))
	// Body and a pipelined second request arrive while the watch is armed.
	_, err = io.WriteString(conn, "hello")
	require.NoError(t, err)
	_, err = io.WriteString(conn, "POST /two HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc")
	require.NoError(t, err)

	steps := []struct{ path, want string }{
		{"/one", "POST /one:hello"},
		{"/two", "POST /two:abc"},
		{"/three", "GET /three:"},
	}
	for i, step := range steps {
		if step.path == "/three" {
			_, err = io.WriteString(conn, "GET /three HTTP/1.1\r\nHost: example.test\r\n\r\n")
			require.NoError(t, err)
		}
		if i > 0 {
			require.Equal(t, step.path, waitFor(t, hook.entered, "hook "+step.path))
		}
		select {
		case hook.release <- struct{}{}:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out releasing %s", step.path)
		}
		res := waitFor(t, hook.outcome, "outcome "+step.path)
		require.Equal(t, hookResult{path: step.path, watchFound: true}, res, "a connected client must never be signalled")

		resp, err := http.ReadResponse(br, nil)
		require.NoError(t, err)
		got, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, step.want, string(got))
	}
}
