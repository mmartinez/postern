package runtime_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// upstreamFixture wraps an httptest.NewTLSServer with helpers for the trust
// config the proxy needs on its outbound transport. Centralizes the
// ServerName="example.com" trick — httptest's bundled cert is for
// "example.com" with no 127.0.0.1 IP SAN, so without SNI override the
// upstream handshake fails when the proxy dials by IP.
type upstreamFixture struct {
	srv *httptest.Server
}

func newTLSUpstream(t *testing.T) *upstreamFixture {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	return &upstreamFixture{srv: srv}
}

func (u *upstreamFixture) URL() string { return u.srv.URL }

func (u *upstreamFixture) Close() { u.srv.Close() }

func (u *upstreamFixture) TLSConfig() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(u.srv.Certificate())
	return &tls.Config{
		RootCAs:    pool,
		ServerName: "example.com",
		MinVersion: tls.VersionTLS12,
	}
}

var _ = require.New // keep require import non-dead if helpers go unused
