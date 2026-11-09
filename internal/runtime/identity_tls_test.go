package runtime_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/runtime"
)

func TestTLSProxyRestrictsNamesAndProtocol(t *testing.T) {
	t.Parallel()
	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{CA: root, Addr: "127.0.0.1:0", Authenticator: broker.NewEngine(nil), ListenerTLSNames: []string{"localhost"}})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	defer func() { cancel(); require.NoError(t, <-done) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	pool := x509.NewCertPool()
	pool.AddCert(root.Cert)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", rt.Addr(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
	require.NoError(t, err)
	require.Equal(t, "http/1.1", conn.ConnectionState().NegotiatedProtocol)
	require.NoError(t, conn.Close())
	for _, cfg := range []*tls.Config{
		{RootCAs: pool, ServerName: "unconfigured.test", MinVersion: tls.VersionTLS12},
		{RootCAs: x509.NewCertPool(), ServerName: "localhost", MinVersion: tls.VersionTLS12},
	} {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", rt.Addr(), cfg)
		if c != nil {
			_ = c.Close()
		}
		require.Error(t, err)
	}
}
