package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	cmd.SetArgs([]string{"add", "agent", "--config", path, "--exec", filepath.Join(t.TempDir(), "missing")})
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
