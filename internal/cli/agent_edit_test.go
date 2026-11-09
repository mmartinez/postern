package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

func TestRotationPreservesEnrollmentComments(t *testing.T) {
	t.Parallel()
	_, hash, err := identity.Generate()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "# operator header\nproxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\nagents:\n  - name: agent # name comment\n    # verifier comment\n    key_sha256: " + hash + " # value comment\n"
	require.NoError(t, os.WriteFile(path, []byte(raw), 0o600))
	_, nextHash, err := identity.Generate()
	require.NoError(t, err)
	require.NoError(t, editAgentConfig(path, "rotate", config.Agent{Name: "agent", KeySHA256: nextHash}))
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	for _, comment := range []string{"operator header", "name comment", "verifier comment", "value comment"} {
		require.True(t, strings.Contains(string(after), comment), "rotation lost a configuration comment")
	}
}

func TestEnrollmentRefusesReadOnlyAndConcurrentEditor(t *testing.T) {
	t.Parallel()
	_, hash, err := identity.Generate()
	require.NoError(t, err)
	for _, locked := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		raw := []byte("proxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n  client_auth: required\n")
		require.NoError(t, os.WriteFile(path, raw, 0o600))
		if locked {
			require.NoError(t, os.WriteFile(path+".enrollment-lock", nil, 0o600))
		} else {
			require.NoError(t, os.Chmod(path, 0o400))
		}
		err := editAgentConfig(path, "add", config.Agent{Name: "agent", KeySHA256: hash})
		require.Error(t, err)
		after, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, raw, after)
	}
}
