package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elazarl/goproxy"
	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/identity"
)

func TestRevokedTunnelErrorsNeverInsertHTTPFrames(t *testing.T) {
	t.Parallel()
	p := identity.NewPrincipal("agent")
	p.Revoke()
	req := httptest.NewRequest(http.MethodConnect, "https://example.test", nil)
	req = req.WithContext(identity.WithPrincipal(req.Context(), p))
	gp := newConnErrProxy(t)
	var output bytes.Buffer
	gp.ConnectionErrHandler(&output, &goproxy.ProxyCtx{Req: req}, context.Canceled)
	require.Zero(t, output.Len(), "revocation inserted an HTTP error into a tunnel")
}

func TestLateUpstreamAcquisitionIsClosedAfterRevocation(t *testing.T) {
	t.Parallel()
	slot := &closeSlot{}
	slot.close()
	client, server := net.Pipe()
	defer func() { _ = client.Close(); _ = server.Close() }()
	slot.attach(client)
	_, err := server.Write([]byte("data"))
	require.Error(t, err)
}

func TestAdmissionBodyPreservesScrubbingEligibility(t *testing.T) {
	t.Parallel()
	body := &admissionBody{ReadCloser: io.NopCloser(strings.NewReader("response")), release: func() {}}
	defer func() { _ = body.Close() }()
	require.True(t, bodyIsScrubbable(&http.Response{Body: body, StatusCode: http.StatusOK, Request: httptest.NewRequest(http.MethodGet, "http://example.test", nil)}))
}

func TestAdmissionBodyPreservesWritableUpgrade(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = server.Close() }()
	released := false
	body := wrapAdmissionBody(client, func() { released = true })
	_, writable := body.(io.ReadWriter)
	require.True(t, writable, "upgrade lost duplex interface")
	require.NoError(t, body.Close())
	require.True(t, released, "upgrade close did not release admission")
}
