package proxy_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/proxy"
)

// The inner-request guard binds every decrypted request on an intercepted
// tunnel to the CONNECT authority. These tests drive raw HTTP/1.1 over the
// MITM connection because Go's http.Client never emits the absolute-form and
// cross-scheme request lines the guard exists for.

const guardBadBody = "postern: bad gateway\n"

// mitmTunnel is an established MITM connection: the CONNECT succeeded and the
// TLS handshake against postern's minted leaf completed. Responses are read
// through the TLS connection; only the plaintext CONNECT exchange runs
// outside it.
type mitmTunnel struct {
	conn *tls.Conn
	// br wraps conn and is reused across responses: go1.26's
	// http.ReadResponse needs a *bufio.Reader and may buffer ahead into
	// the next response.
	br *bufio.Reader
}

// openMITMTunnel CONNECTs to target through the proxy and completes the MITM
// handshake, trusting only postern's CA.
func openMITMTunnel(t *testing.T, proxyURL, target string, root *ca.CA) *mitmTunnel {
	t.Helper()
	u, err := url.Parse(proxyURL)
	require.NoError(t, err)
	conn, err := net.Dial("tcp", u.Host)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "CONNECT must be accepted")

	host, _, err := net.SplitHostPort(target)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	tc := tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	})
	require.NoError(t, tc.Handshake())
	return &mitmTunnel{conn: tc, br: bufio.NewReader(tc)}
}

// roundTrip writes a hand-crafted HTTP/1.1 request over the tunnel, reads one
// response to completion, and returns its status and body. A per-call
// deadline keeps a missing response a fast test failure rather than a hang.
func (tn *mitmTunnel) roundTrip(t *testing.T, raw string) (int, string) {
	t.Helper()
	require.NoError(t, tn.conn.SetDeadline(time.Now().Add(10*time.Second)))
	_, err := io.WriteString(tn.conn, raw)
	require.NoError(t, err)
	resp, err := http.ReadResponse(tn.br, &http.Request{Method: http.MethodGet})
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(b)
}

// startGuardProxy builds an always-intercepting proxy in front of upstream
// and returns its URL plus the postern CA the tunnel client must trust.
func startGuardProxy(t *testing.T, upstream *httptest.Server, logBuf io.Writer) (string, *ca.CA) {
	t.Helper()
	root := fixtureCA(t)
	p, err := proxy.New(proxy.Config{
		CA:          root,
		Minter:      fixtureMinter(t, root),
		Logger:      slog.New(slog.NewTextHandler(logBuf, nil)),
		UpstreamTLS: upstreamTLS(t, upstream),
	})
	require.NoError(t, err)
	return startProxy(t, p), root
}

// TestRedTeam_InnerRequest_CrossHostAbsoluteForm_FailsClosed pins the
// semantic-drift fix: an absolute-form inner request naming another host must
// not be forwarded under passthrough policy — it fails closed with the
// constant 502 body and the upstream is never dialed.
func TestRedTeam_InnerRequest_CrossHostAbsoluteForm_FailsClosed(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	logBuf := &lockedBuffer{}
	proxyURL, root := startGuardProxy(t, upstream, logBuf)

	target := strings.TrimPrefix(upstream.URL, "https://")
	tn := openMITMTunnel(t, proxyURL, target, root)

	status, body := tn.roundTrip(t, "GET https://other.example/v1/steal HTTP/1.1\r\nHost: other.example\r\n\r\n")
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, guardBadBody, body)
	require.Zero(t, hits.Load(), "cross-host inner request must NOT be forwarded upstream")
	require.Contains(t, logBuf.String(), "rejecting non-brokered inner host")
}

// TestRedTeam_InnerRequest_CrossSchemeAbsoluteForm_NoPanic pins the
// crash-per-tunnel fix: a cross-scheme absolute-form inner request used to
// crash the logging handler on a nil req.URL (goproxy re-parse failure) or,
// since goproxy v1.9.0, keeps its own host after the tunnel scheme is forced
// onto it. Either way the guard must reject it with the generic 502 before
// any handler can dereference a nil req.URL, so the tunnel closes cleanly
// with no panic or stack trace in the logs.
func TestRedTeam_InnerRequest_CrossSchemeAbsoluteForm_NoPanic(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
	}))
	t.Cleanup(upstream.Close)

	logBuf := &lockedBuffer{}
	proxyURL, root := startGuardProxy(t, upstream, logBuf)

	target := strings.TrimPrefix(upstream.URL, "https://")
	tn := openMITMTunnel(t, proxyURL, target, root)

	status, body := tn.roundTrip(t, "GET http://evil.example/v1/pwn HTTP/1.1\r\nHost: evil.example\r\n\r\n")
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, guardBadBody, body)
	require.Zero(t, hits.Load(), "cross-scheme inner request must NOT be forwarded upstream")

	// The rejection is deliberate (an INFO log line), never a recovered
	// panic: no panic text and no goroutine dump may reach the logs.
	logs := logBuf.String()
	require.Contains(t, logs, "msg=\"rejecting ")
	require.NotContains(t, logs, "panic", "no panic may reach the logs")
	require.NotContains(t, logs, "goroutine", "no stack trace may reach the logs")
}

// TestRedTeam_InnerRequest_SameHostAbsoluteForm_Forwards pins the positive
// case: an absolute-form inner request whose host matches the CONNECT
// authority still forwards normally.
func TestRedTeam_InnerRequest_SameHostAbsoluteForm_Forwards(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	proxyURL, root := startGuardProxy(t, upstream, &lockedBuffer{})

	target := strings.TrimPrefix(upstream.URL, "https://")
	tn := openMITMTunnel(t, proxyURL, target, root)

	status, body := tn.roundTrip(t, "GET https://"+target+"/v1/ok HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "ok", body)
	require.Equal(t, int64(1), hits.Load(), "same-host inner request must reach the upstream")
}

// TestRedTeam_InnerRequest_SequentialOverOneTunnel pins that the authority
// stash is carried on every inner request of a tunnel, not just the first:
// allowed and rejected requests interleave over a single connection and each
// is judged independently.
func TestRedTeam_InnerRequest_SequentialOverOneTunnel(t *testing.T) {
	t.Parallel()

	var hits atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(upstream.Close)

	proxyURL, root := startGuardProxy(t, upstream, &lockedBuffer{})

	target := strings.TrimPrefix(upstream.URL, "https://")
	tn := openMITMTunnel(t, proxyURL, target, root)

	// 1. Relative-form: unchanged behavior, forwards.
	status, body := tn.roundTrip(t, "GET /v1/a HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "ok", body)

	// 2. Cross-host absolute-form: rejected without upstream contact.
	status, body = tn.roundTrip(t, "GET https://other.example/v1/b HTTP/1.1\r\nHost: other.example\r\n\r\n")
	require.Equal(t, http.StatusBadGateway, status)
	require.Equal(t, guardBadBody, body)

	// 3. Same-host absolute-form after a rejection: the stash still binds,
	// so this forwards — proving per-request evaluation on a live tunnel.
	status, body = tn.roundTrip(t, "GET https://"+target+"/v1/c HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "ok", body)

	require.Equal(t, int64(2), hits.Load(), "exactly the two bound requests must reach the upstream")
}
