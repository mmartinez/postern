package runtime_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func TestRevocationCancelsPendingApprovalWithoutExecution(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	var hits atomic.Int32
	u := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer u.Close()
	target, err := url.Parse(u.URL)
	require.NoError(t, err)
	rules := []broker.Rule{{Host: target.Hostname(), SecretRef: "test://ref", Injection: broker.InjectSpec{Type: broker.InjectHeader, Name: "Authorization", Template: "{{ CREDENTIAL }}"}, Approval: &config.Approval{}}}
	e := broker.NewEngine(rules)
	require.NoError(t, e.Publish(rules, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	opened, closed := make(chan struct{}), make(chan struct{})
	gate := broker.NewGate(t.Context(), broker.GateConfig{Approver: approverFunc(func(ctx context.Context, _ string) (broker.Outcome, error) {
		close(opened)
		<-ctx.Done()
		close(closed)
		return broker.OutcomeUnavailable, ctx.Err()
	})})
	resolver := &countingResolver{}
	root := fixtureCA(t)
	rt, err := runtime.New(runtime.Options{
		CA: root, Addr: "127.0.0.1:0", Authenticator: e,
		PreUpstreamHandler: broker.Hook(e, resolver, config.OnNoMatchBlock, 0, true, nil, gate), //nolint:bodyclose // proxy owns synthetic response bodies
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	serverDone := make(chan error, 1)
	go func() { serverDone <- rt.Run(ctx) }()
	defer func() { cancel(); require.NoError(t, <-serverDone) }()
	require.NoError(t, waitForListening(rt, 2*time.Second))
	proxyURL := &url.URL{Scheme: "http", Host: rt.Addr(), User: url.UserPassword("agent", key)}
	trust := x509.NewCertPool()
	trust.AddCert(root.Cert)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: trust, MinVersion: tls.VersionTLS12}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		resp, err := client.Get(u.URL)
		if err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-opened:
	case <-time.After(2 * time.Second):
		t.Fatal("approval did not open")
	}
	require.NoError(t, e.Publish(rules, nil))
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("revocation did not close approval")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("revoked client retained access")
	}
	require.Zero(t, resolver.calls.Load())
	require.Zero(t, hits.Load())
}
