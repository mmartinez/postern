package config_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/mmartinez/postern/internal/config"
)

// TestPosternConfigInitWritesValidDefault builds the postern binary, runs
// `postern config init --config <tmpdir>/config.yaml`, and asserts the
// resulting file unmarshals into a Config. SPEC §12 acceptance row.
func TestPosternConfigInitWritesValidDefault(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test; build cost")
	}

	bin := buildPostern(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")

	out, err := exec.Command(bin, "config", "init", "--config", cfg).CombinedOutput() //nolint:gosec // test invocation
	require.NoErrorf(t, err, "postern config init failed: %s", out)

	raw, err := os.ReadFile(cfg) //nolint:gosec // test path
	require.NoError(t, err)

	var c config.Config
	require.NoError(t, yaml.Unmarshal(raw, &c), "default config must parse")
	require.GreaterOrEqual(t, len(c.Rules), 1, "default must include at least one rule")
}

// TestPosternConfigInitRefusesOverwrite verifies init does not clobber an
// existing config unless --force is passed.
func TestPosternConfigInitRefusesOverwrite(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test; build cost")
	}

	bin := buildPostern(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("# pre-existing\n"), 0o600))

	out, err := exec.Command(bin, "config", "init", "--config", cfg).CombinedOutput() //nolint:gosec // test
	require.Errorf(t, err, "expected non-zero exit but got success: %s", out)
	if !strings.Contains(string(out), "--force") {
		t.Errorf("error message should mention --force; got: %s", out)
	}

	// Existing file must be untouched.
	raw, err := os.ReadFile(cfg) //nolint:gosec // test
	require.NoError(t, err)
	require.Equal(t, "# pre-existing\n", string(raw))

	// With --force it should overwrite.
	out, err = exec.Command(bin, "config", "init", "--config", cfg, "--force").CombinedOutput() //nolint:gosec // test
	require.NoErrorf(t, err, "expected --force to succeed: %s", out)
	raw, err = os.ReadFile(cfg) //nolint:gosec // test
	require.NoError(t, err)
	require.NotEqual(t, "# pre-existing\n", string(raw), "force should overwrite")
}

// buildPostern compiles cmd/postern into a tempdir binary and returns the path.
// Cached per test binary via t.TempDir parent to avoid rebuilding per subtest;
// each Test* function gets its own dir which is acceptable for M1.
func buildPostern(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "postern")
	// Module root is three dirs up from internal/config.
	out, err := exec.Command("go", "build", "-o", bin, "../../cmd/postern").CombinedOutput() //nolint:gosec // test
	require.NoErrorf(t, err, "go build failed: %s", out)
	return bin
}
