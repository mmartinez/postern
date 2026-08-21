package proxy

import (
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNewUpstreamTransport_DefaultTimeouts pins the outbound transport's
// timeout budget exactly. goproxy's own default transport sets none of
// these, so a regression here silently re-opens the "stalled upstream pins
// a goroutine and an fd forever" hole.
func TestNewUpstreamTransport_DefaultTimeouts(t *testing.T) {
	t.Parallel()

	tr := newUpstreamTransport(Config{})

	require.NotNil(t, tr.DialContext, "upstream dials (requests AND CONNECT tunnels) must go through the bounded dialer")
	require.True(t, reflect.ValueOf(tr.Proxy).Pointer() == reflect.ValueOf(http.ProxyFromEnvironment).Pointer(),
		"proxy-from-environment must be preserved")
	require.Equal(t, 10*time.Second, tr.TLSHandshakeTimeout)
	require.Equal(t, 30*time.Second, tr.ResponseHeaderTimeout)
	require.Equal(t, 90*time.Second, tr.IdleConnTimeout)
	require.Equal(t, 1*time.Second, tr.ExpectContinueTimeout)
	require.True(t, tr.ForceAttemptHTTP2)
	require.Nil(t, tr.TLSClientConfig, "TLS config is applied by New, not the transport constructor")
}

// TestNewUpstreamTransport_TestSeams proves the test-only overrides reach
// the transport so timeout tests do not sleep through production values.
func TestNewUpstreamTransport_TestSeams(t *testing.T) {
	t.Parallel()

	tr := newUpstreamTransport(Config{
		TestDialTimeout:           100 * time.Millisecond,
		TestResponseHeaderTimeout: 50 * time.Millisecond,
	})

	require.Equal(t, 50*time.Millisecond, tr.ResponseHeaderTimeout)
	// The dial timeout lives inside the DialContext closure; it is asserted
	// behaviorally by the tunnel-dial-bound e2e test.
}
