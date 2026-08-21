package runtime_test

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/runtime"
)

// TestRuntime_IdleKeepAliveConnReaped proves the inbound server closes a
// silent keep-alive connection within the (test-injected) idle bound
// instead of holding it forever.
func TestRuntime_IdleKeepAliveConnReaped(t *testing.T) {
	t.Parallel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{
		CA:              root,
		Addr:            "127.0.0.1:0",
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		TestIdleTimeout: 300 * time.Millisecond,
	})
	require.NoError(t, err)

	ctx := t.Context()
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	t.Cleanup(func() {
		<-done
	})

	conn, err := net.DialTimeout("tcp", rt.Addr(), 2*time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// One absolute-form request over the connection, then go silent — the
	// keep-alive conn is now idle from the server's perspective.
	req := "GET " + upstream.URL + "/ HTTP/1.1\r\nHost: " + hostOnly(t, upstream.URL) + "\r\n\r\n"
	_, err = conn.Write([]byte(req))
	require.NoError(t, err)
	fakeReq, err := http.NewRequest(http.MethodGet, upstream.URL, http.NoBody)
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, fakeReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)

	// The server must close the idle conn well inside a generous bound.
	idleStart := time.Now()
	_ = conn.SetDeadline(idleStart.Add(5 * time.Second))
	_, err = reader.ReadByte()
	require.Error(t, err, "idle keep-alive connection was never closed")
	require.Less(t, time.Since(idleStart), 3*time.Second,
		"idle conn closed after %v — IdleTimeout not in effect", time.Since(idleStart))
}

// hostOnly strips the scheme and port from an httptest URL for the Host
// header of a hand-rolled request.
func hostOnly(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u.Hostname()
}
