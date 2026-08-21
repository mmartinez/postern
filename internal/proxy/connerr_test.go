package proxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"
)

// errMintFailure is representative of the error goproxy's httpError would
// leak: a MITM leaf-signing failure naming the CA path and internal detail.
var errMintFailure = errors.New("mint leaf for internal-vault.corp: open /home/dev/.postern/ca.key: permission denied")

// errDialFailure is representative of a tunnel-dial error: OS error text
// plus an internal address — a network-topology oracle if echoed to the client.
var errDialFailure = errors.New("dial tcp 10.42.0.7:8443: connect: connection refused")

// newConnErrProxy builds a proxy server with the sanitized connection error
// handler installed, for direct invocation of gp.ConnectionErrHandler.
func newConnErrProxy(t *testing.T) *goproxy.ProxyHttpServer {
	t.Helper()
	gp := goproxy.NewProxyHttpServer()
	installConnectionErrHandler(gp, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NotNil(t, gp.ConnectionErrHandler)
	return gp
}

// TestConnectionErrHandler_HTTPResponseWriter covers the branch where
// goproxy hands us a real http.ResponseWriter (e.g. the plain-HTTP error
// path): the client must see exactly the constant bad-gateway body with a
// 502 status and none of the underlying error text.
func TestConnectionErrHandler_HTTPResponseWriter(t *testing.T) {
	t.Parallel()

	for name, err := range map[string]error{"mint": errMintFailure, "dial": errDialFailure} {
		t.Run(name, func(t *testing.T) {
			gp := newConnErrProxy(t)
			rec := httptest.NewRecorder()

			gp.ConnectionErrHandler(rec, &goproxy.ProxyCtx{}, err)

			require.Equal(t, 502, rec.Code)
			require.Equal(t, badGatewayBody, rec.Body.String())
			require.NotContains(t, rec.Body.String(), "mint")
			require.NotContains(t, rec.Body.String(), "ca.key")
			require.NotContains(t, rec.Body.String(), "10.42.0.7")
			require.NotContains(t, rec.Body.String(), "connection refused")
		})
	}
}

// TestConnectionErrHandler_RawWriter covers the hijacked-stream branch:
// tunnel dial failures and mid-tunnel copy errors arrive on a bare
// io.Writer after the 200 Connection established frame may already be out.
// The response must mirror goproxy's raw HTTP/1.1 frame shape but carry the
// constant body.
func TestConnectionErrHandler_RawWriter(t *testing.T) {
	t.Parallel()

	gp := newConnErrProxy(t)
	var buf bytes.Buffer

	gp.ConnectionErrHandler(&buf, &goproxy.ProxyCtx{}, errDialFailure)

	out := buf.String()
	require.True(t, strings.HasPrefix(out, "HTTP/1.1 502 Bad Gateway\r\n"), "raw branch must emit a parseable 502 status line, got %q", out)
	require.Contains(t, out, "Content-Length: "+strconv.Itoa(len(badGatewayBody))+"\r\n")
	require.True(t, strings.HasSuffix(out, "\r\n\r\n"+badGatewayBody), "body must be exactly the constant bad-gateway body")
	require.NotContains(t, out, "10.42.0.7")
	require.NotContains(t, out, "connection refused")
}

// TestConnectionErrHandler_DeadPeerDoesNotPanic proves the mid-tunnel path
// tolerates a peer that has already hung up: writing to a closed pipe must
// be ignored, never panic.
func TestConnectionErrHandler_DeadPeerDoesNotPanic(t *testing.T) {
	t.Parallel()

	gp := newConnErrProxy(t)
	client, server := net.Pipe()
	require.NoError(t, server.Close()) // peer gone mid-tunnel
	defer func() { _ = client.Close() }()

	gp.ConnectionErrHandler(client, &goproxy.ProxyCtx{}, errDialFailure)
}
