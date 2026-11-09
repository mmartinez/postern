package runtime_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
	"github.com/mmartinez/postern/internal/runtime"
)

func TestRevocationClosesBusyMITMStream(t *testing.T) {
	t.Parallel()
	for _, encrypted := range []bool{false} {
		name := "plaintext"
		if encrypted {
			name = "tls"
		}
		t.Run(name, func(t *testing.T) { checkRevokedMITMStream(t, encrypted) })
	}
}

func checkRevokedMITMStream(t *testing.T, encrypted bool) {
	t.Helper()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	e := broker.NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	upstreamClosed := make(chan struct{})
	u := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upstreamClosed)
	}))
	defer u.Close()
	pool := x509.NewCertPool()
	pool.AddCert(u.Certificate())
	root := fixtureCA(t)

	rt, err := runtime.New(runtime.Options{
		CA: root, Addr: "127.0.0.1:0", Authenticator: e,
		UpstreamTLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	defer func() { cancel(); require.NoError(t, <-done) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	_, port, err := net.SplitHostPort(rt.Addr())
	require.NoError(t, err)
	proxyURL := &url.URL{Scheme: "http", Host: net.JoinHostPort("localhost", port), User: url.UserPassword("agent", key)}
	if encrypted {
		proxyURL.Scheme = "https"
	}
	trust := x509.NewCertPool()
	trust.AddCert(root.Cert)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := client.Get(u.URL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	first := make([]byte, len("data: ready\n\n"))
	_, err = io.ReadFull(resp.Body, first)
	require.NoError(t, err)
	require.NoError(t, e.Publish(nil, nil))
	_, err = io.ReadAll(resp.Body)
	require.Error(t, err)
	select {
	case <-upstreamClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("revocation left upstream active")
	}
}
