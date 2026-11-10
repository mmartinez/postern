package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

func TestAgentRequiresRecipientBeforeMutation(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("# operator comment\nproxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	cmd := NewAgentCmd()
	cmd.SetArgs([]string{"add", "agent", "--config", path})
	require.Error(t, cmd.Execute())
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, raw, after)
}

func TestAgentChild(_ *testing.T) {
	if os.Getenv("POSTERN_LAUNCHER_TEST") != "1" {
		return
	}
	if os.Getenv("NODE_USE_ENV_PROXY") != "1" {
		os.Exit(15)
	}
	u, err := url.Parse(os.Getenv("HTTPS_PROXY"))
	if err != nil || u.User == nil {
		os.Exit(11)
	}
	key, ok := u.User.Password()
	if !ok || !strings.HasPrefix(key, "pst_") {
		os.Exit(12)
	}
	raw, err := os.ReadFile(os.Getenv("POSTERN_ENROLLMENT_TEST"))
	if err != nil {
		os.Exit(13)
	}
	hash := sha256.Sum256([]byte(key))
	if !bytes.Contains(raw, []byte(hex.EncodeToString(hash[:]))) || bytes.Contains(raw, []byte(key)) {
		os.Exit(14)
	}
	os.Exit(0)
}

func TestAgentLauncherLifecycle(t *testing.T) {
	var probes atomic.Int32

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("# operator comment\nproxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n"), 0o600))
	t.Setenv("POSTERN_LAUNCHER_TEST", "1")
	t.Setenv("POSTERN_ENROLLMENT_TEST", path)
	executable, err := os.Executable()
	require.NoError(t, err)
	run := func(args ...string) string {
		t.Helper()
		cmd := NewAgentCmd()
		var output bytes.Buffer
		cmd.SetOut(&output)
		cmd.SetErr(&output)
		cmd.SetArgs(args)
		require.NoError(t, cmd.Execute())
		require.False(t, strings.Contains(output.String(), "pst_"), "key appeared in command output")
		return output.String()
	}
	proxy := enrollmentTestServer(t, path, &probes)
	defer proxy.Close()
	run("add", "agent", "--config", path, "--proxy", proxy.URL, "--exec", executable, "-test.run=^TestAgentChild$")
	require.GreaterOrEqual(t, probes.Load(), int32(2), "client launched before server confirmed enrollment")
	before, err := config.LoadForCLI(path, true)
	require.NoError(t, err)
	require.Equal(t, "agent\n", run("list", "--config", path))
	run("rotate", "agent", "--config", path, "--proxy", proxy.URL, "--exec", executable, "-test.run=^TestAgentChild$")
	after, err := config.LoadForCLI(path, true)
	require.NoError(t, err)
	require.True(t, before.Agents[0].KeySHA256 != after.Agents[0].KeySHA256, "rotation did not replace verifier")
	run("remove", "agent", "--config", path)
	removed, err := config.LoadForCLI(path, true)
	require.NoError(t, err)
	require.Zero(t, len(removed.Agents))
}

func TestRemoteEnrollmentArtifact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enrollment.yaml")
	t.Setenv("POSTERN_LAUNCHER_TEST", "1")
	t.Setenv("POSTERN_ENROLLMENT_TEST", path)
	executable, err := os.Executable()
	require.NoError(t, err)
	cmd := NewAgentCmd()
	cmd.SetArgs([]string{"add", "remote", "--enrollment-out", path, "--proxy", "https://proxy.example.test:1701", "--exec", executable, "-test.run=^TestAgentChild$"})
	require.NoError(t, cmd.Execute())
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestRequiredAuthIsWiredWithoutBrokerRules(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("proxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n"), 0o600))
	bundle, err := buildBrokerHook(t.Context(), nil, path, true, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NotNil(t, bundle.authenticator)
	require.NotNil(t, bundle.engine)
	require.NotEmpty(t, bundle.cfgPath)
}

func TestAgentLaunchFailureRetainsEnrollment(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("# operator comment\nproxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n"), 0o600))
	var output bytes.Buffer
	cmd := NewAgentCmd()
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	var probes atomic.Int32
	proxy := enrollmentTestServer(t, path, &probes)
	defer proxy.Close()
	cmd.SetArgs([]string{"add", "agent", "--config", path, "--proxy", proxy.URL, "--exec", filepath.Join(t.TempDir(), "missing")})
	err := cmd.Execute()
	require.Error(t, err)
	require.NotContains(t, err.Error(), "pst_")
	cfg, err := config.LoadForCLI(path, true)
	require.NoError(t, err)
	require.True(t, len(cfg.Agents) == 1, "missing enrollment")
	require.Equal(t, "agent", cfg.Agents[0].Name)
	require.False(t, strings.Contains(output.String(), cfg.Agents[0].KeySHA256), "command exposed verifier")
	require.False(t, strings.Contains(output.String(), "pst_"), "command output contained key material")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(raw), "# operator comment")
}

func enrollmentTestServer(t *testing.T, path string, probes *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if probes.Add(1) == 1 {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		if r.Method != http.MethodOptions || r.URL.Path != "/.well-known/postern/client-auth" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Proxy-Authorization"), "Basic "))
		if err != nil {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		name, key, ok := strings.Cut(string(raw), ":")
		cfg, err := config.LoadForCLI(path, true)
		if err != nil || !ok {
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		digest := sha256.Sum256([]byte(key))
		for _, agent := range cfg.Agents {
			if agent.Name == name && agent.KeySHA256 == hex.EncodeToString(digest[:]) {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
}
