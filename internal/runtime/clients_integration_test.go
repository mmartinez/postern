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
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
	"github.com/mmartinez/postern/internal/runtime"
)

func TestClientsAgainstProxyImplementation(t *testing.T) {
	if os.Getenv("POSTERN_CLIENT_CHECK") != "1" {
		t.Skip("opt-in external client compatibility check")
	}
	for _, client := range []string{"curl", "go", "node", "requests", "httpx", "urllib", "client-one", "client-two"} {
		t.Run(client, func(t *testing.T) { checkExternalClient(t, client) })
	}
}

func TestClientTransportChild(_ *testing.T) {
	if os.Getenv("POSTERN_TEST_GO_CLIENT") != "1" {
		return
	}
	u, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil {
		os.Exit(11)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(u)
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}
	resp, err := client.Get(os.Getenv("POSTERN_TEST_TARGET"))
	if err != nil {
		os.Exit(12)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		os.Exit(13)
	}
	os.Exit(0)
}

func checkExternalClient(t *testing.T, client string) {
	t.Helper()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	dummyAPIKey, _, err := identity.Generate()
	require.NoError(t, err)
	e := broker.NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	reached := make(chan bool, 1)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case reached <- len(r.Header.Values("Proxy-Authorization")) == 0:
		default:
		}
		_, _ = io.Copy(io.Discard, r.Body)
		if client == "client-one" || client == "client-two" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(upstream.Certificate())
	root := fixtureCA(t)
	caPath := filepath.Join(t.TempDir(), "public-ca.pem")
	require.NoError(t, os.WriteFile(caPath, root.CertPEM, 0o600))
	var names []string
	if client != "urllib" {
		names = []string{"localhost"}
	}
	rt, err := runtime.New(runtime.Options{
		CA: root, Addr: "127.0.0.1:0", Authenticator: e, ListenerTLSNames: names,
		UpstreamTLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		PreUpstreamHandler: func(r *http.Request) *http.Response {
			if r.URL.Host != target.Host || identity.FromContext(r.Context()) == nil {
				return &http.Response{Request: r, StatusCode: http.StatusBadGateway, Header: make(http.Header), Body: http.NoBody}
			}
			return nil
		},
	})
	require.NoError(t, err)
	serverCtx, stop := context.WithCancel(t.Context())
	serverDone := make(chan error, 1)
	go func() { serverDone <- rt.Run(serverCtx) }()
	defer func() { stop(); require.NoError(t, <-serverDone) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	_, port, err := net.SplitHostPort(rt.Addr())
	require.NoError(t, err)
	proxyURL := &url.URL{Scheme: "https", Host: net.JoinHostPort("localhost", port), User: url.UserPassword("agent", key)}
	if client == "urllib" {
		proxyURL.Scheme = "http"
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "testdata/client-check.sh", client)
	executable, err := os.Executable()
	require.NoError(t, err)
	cmd.Env = append(os.Environ(), "HTTPS_PROXY="+proxyURL.String(), "HTTP_PROXY="+proxyURL.String(), "https_proxy="+proxyURL.String(), "http_proxy="+proxyURL.String(), "NO_PROXY=", "no_proxy=", "SSL_CERT_FILE="+caPath, "NODE_EXTRA_CA_CERTS="+caPath, "REQUESTS_CA_BUNDLE="+caPath, "POSTERN_TEST_TARGET="+upstream.URL, "POSTERN_TEST_API_KEY="+dummyAPIKey)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.Env = append(cmd.Env, "POSTERN_GO_CLIENT="+executable)
	finished := make(chan error, 1)
	go func() { finished <- cmd.Run() }()
	select {
	case clean := <-reached:
		require.True(t, clean, "proxy authorization leaked upstream")
		cancel()
		<-finished
	case <-finished:
		select {
		case clean := <-reached:
			require.True(t, clean)
		default:
			t.Fatal("client did not reach the protected upstream")
		}
	case <-ctx.Done():
		<-finished
		t.Fatal("client transport verification timed out")
	}
}
