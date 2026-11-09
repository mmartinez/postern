package runtime_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
	"github.com/mmartinez/postern/internal/runtime"
)

func TestAuthenticatedCONNECTCannotSwitchInnerIdentity(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	otherKey, otherHash, err := identity.Generate()
	require.NoError(t, err)
	e := broker.NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}, {Name: "other", KeySHA256: otherHash}}))
	var hits atomic.Int32
	u := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Proxy-Authorization")) != 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer u.Close()
	pool := x509.NewCertPool()
	pool.AddCert(u.Certificate())
	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{
		CA: root, Addr: "127.0.0.1:0", Authenticator: e,
		UpstreamTLS: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		PreUpstreamHandler: func(r *http.Request) *http.Response {
			p := identity.FromContext(r.Context())
			if p == nil || p.Name() != "agent" || len(r.Header.Values("Proxy-Authorization")) != 0 {
				return &http.Response{Request: r, StatusCode: http.StatusForbidden, Header: make(http.Header), Body: http.NoBody}
			}
			return nil
		},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- rt.Run(ctx) }()
	defer func() { cancel(); require.NoError(t, <-done) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	proxyURL := &url.URL{Scheme: "http", Host: rt.Addr(), User: url.UserPassword("agent", key)}
	trust := x509.NewCertPool()
	trust.AddCert(root.Cert)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	for range 2 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, u.URL, nil)
		require.NoError(t, err)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("other:"+otherKey)))
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
	}
	require.EqualValues(t, 2, hits.Load())
}
