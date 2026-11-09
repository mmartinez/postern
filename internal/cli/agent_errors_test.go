package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidEnrollmentCannotMutateConfig(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"name", []string{"add", "invalid.name", "--exec", "unused"}},
		{"unknown flag", []string{"add", "agent", "--unknown", "--exec", "unused"}},
		{"list name", []string{"list", "agent"}},
		{"userinfo", []string{"add", "agent", "--proxy", "https://user@proxy.test:1701", "--exec", "unused"}},
		{"query", []string{"add", "agent", "--proxy", "https://proxy.test:1701/?auth=ignored", "--exec", "unused"}},
		{"scheme", []string{"add", "agent", "--proxy", "ftp://proxy.test:1701", "--exec", "unused"}},
		{"missing rotation", []string{"rotate", "missing", "--exec", "unused"}},
		{"missing removal", []string{"remove", "missing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.yaml")
			raw := []byte("proxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n")
			require.NoError(t, os.WriteFile(path, raw, 0o600))
			cmd := NewAgentCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			args := []string{tc.args[0], "--config", path}
			args = append(args, tc.args[1:]...)
			cmd.SetArgs(args)
			require.Error(t, cmd.Execute())
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, raw, after)
		})
	}
}

func TestBootstrapRefusesUnauthenticatedSnippetInRequiredMode(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("proxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n"), 0o600))
	_, err := resolveBootstrapListen(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "agent add")
}

func TestEnrollmentConflictsPreserveOperatorArtifact(t *testing.T) {
	t.Parallel()
	for _, conflict := range []string{"existing artifact", "live config", "missing ca"} {
		t.Run(conflict, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "enrollment.yaml")
			raw := []byte("operator-owned artifact\n")
			require.NoError(t, os.WriteFile(path, raw, 0o600))
			args := []string{"add", "agent", "--enrollment-out", path, "--proxy", "https://proxy.example.test:1701"}
			if conflict == "live config" {
				args = append(args, "--config", filepath.Join(t.TempDir(), "config.yaml"))
			}
			if conflict == "missing ca" {
				args = append(args, "--ca", filepath.Join(t.TempDir(), "missing.pem"))
			}
			args = append(args, "--exec", "unused")
			cmd := NewAgentCmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(args)
			require.Error(t, cmd.Execute())
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, raw, after)
		})
	}
}
