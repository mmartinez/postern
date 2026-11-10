package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

func TestValidCredentialsBypassExhaustedLoopbackBudget(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	e := broker.NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	root, err := ca.Generate(time.Now())
	require.NoError(t, err)
	minter, err := ca.NewMinter(root, 1, time.Now)
	require.NoError(t, err)
	p, err := New(Config{CA: root, Minter: minter, Authenticator: e, PreUpstreamHandler: func(req *http.Request) *http.Response {
		return &http.Response{Request: req, StatusCode: http.StatusNoContent, Header: make(http.Header), Body: http.NoBody}
	}})
	require.NoError(t, err)
	for range 9 {
		_, release, ok := p.throttle.failure("127.0.0.1:1")
		require.True(t, ok)
		defer release()
	}
	_, _, ok := p.throttle.failure("[::1]:2")
	require.False(t, ok)
	p.throttle.now = func() time.Time { t.Fatal("valid credentials entered the failure-delay path"); return time.Time{} }
	r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "127.0.0.2:3"
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("agent:"+key)))
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	require.Equal(t, http.StatusNoContent, w.Code)
}
