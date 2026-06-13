package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExec_ErrorPaths drives the real binary through the `postern exec`
// failure modes that need no credential vendor: a missing command, a missing
// config, and a config with nothing to inject. The resolve-and-replace happy
// path needs live vendor credentials, so it is covered in-process by the
// runExec unit tests (exec_test.go) with a fake resolver instead.
func TestExec_ErrorPaths(t *testing.T) {
	// Not Parallel at the top level: go build dominates wall-clock. Build once,
	// then fan the cheap subprocess cases out underneath it.
	bin := buildPosternBinary(t)

	t.Run("no command exits non-zero", func(t *testing.T) {
		t.Parallel()
		cmd := exec.Command(bin, "exec") //nolint:gosec // test-built binary
		cmd.Env = filteredEnv()
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "exec with no command must exit non-zero; output: %s", out)
	})

	t.Run("missing config exits non-zero", func(t *testing.T) {
		t.Parallel()
		missing := filepath.Join(t.TempDir(), "nope.yaml")
		cmd := exec.Command(bin, "exec", "--config", missing, "--", "echo", "hi") //nolint:gosec // test-built binary
		cmd.Env = filteredEnv()
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "missing config must exit non-zero; output: %s", out)
	})

	t.Run("config without env block exits non-zero", func(t *testing.T) {
		t.Parallel()
		cfg := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(cfg, []byte(`
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`), 0o600))
		cmd := exec.Command(bin, "exec", "--config", cfg, "--", "echo", "hi") //nolint:gosec // test-built binary
		cmd.Env = filteredEnv()
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "a config with no env: block must exit non-zero; output: %s", out)
		require.Contains(t, string(out), "no env", "error should explain there is nothing to inject; output: %s", out)
	})
}
