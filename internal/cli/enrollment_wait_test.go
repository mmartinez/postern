package cli

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
	"github.com/stretchr/testify/require"
)

func TestEnrollmentWaitUsesProxyTrustAndNeverFollowsRedirects(t *testing.T) {
	t.Parallel()
	key, _, err := identity.Generate()
	require.NoError(t, err)
	var redirected, attempts atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { redirected.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodOptions, r.Method)
		require.Equal(t, "/.well-known/postern/client-auth", r.URL.Path)
		require.NotEmpty(t, r.Header.Get("Proxy-Authorization"))
		require.Empty(t, r.Header.Get("Authorization"))
		if attempts.Add(1) == 1 {
			http.Redirect(w, r, destination.URL, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	bundle := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	require.NoError(t, waitForEnrollment(t.Context(), endpoint, "agent", key, bundle))
	require.Zero(t, redirected.Load(), "probe followed redirect with credentials")
	require.EqualValues(t, 2, attempts.Load())
	require.Error(t, waitForEnrollment(t.Context(), endpoint, "agent", key, filepath.Join(t.TempDir(), "missing")))
	require.NoError(t, os.WriteFile(bundle, []byte("invalid certificate"), 0o600))
	require.Error(t, waitForEnrollment(t.Context(), endpoint, "agent", key, bundle))
}

func TestUnconfirmedEnrollmentDoesNotLaunchOrRollback(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("proxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n"), 0o600))
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { cancel(); w.WriteHeader(http.StatusProxyAuthRequired) }))
	defer server.Close()
	cmd := NewAgentCmd()
	cmd.SetArgs([]string{"add", "agent", "--config", path, "--proxy", server.URL, "--exec", filepath.Join(t.TempDir(), "missing-client")})
	launchErr := cmd.ExecuteContext(ctx)
	require.ErrorContains(t, launchErr, "server did not confirm enrollment")
	require.NotContains(t, launchErr.Error(), "client launch or execution failed")
	cfg, err := config.LoadForCLI(path, true)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	require.False(t, strings.Contains(launchErr.Error(), cfg.Agents[0].KeySHA256))
}
