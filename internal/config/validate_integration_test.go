package config_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestPosternConfigValidateRejectsBadRuleWithLineNumber verifies that
// `config validate` rejects a bad rule and reports a line number.
func TestPosternConfigValidateRejectsBadRuleWithLineNumber(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test; build cost")
	}

	bin := buildPostern(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte(`
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: not-an-op-reference
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`), 0o600))

	out, err := exec.Command(bin, "config", "validate", "--config", cfg).CombinedOutput() //nolint:gosec // test
	require.Errorf(t, err, "validate should exit non-zero on a bad rule; got: %s", out)

	// Must mention secret_ref and include a line number formatted as "N:M".
	if !strings.Contains(string(out), "secret_ref") {
		t.Errorf("output should mention secret_ref; got: %s", out)
	}
	if !regexp.MustCompile(`\b\d+:\d+\b`).Match(out) {
		t.Errorf("output should include a line:column reference; got: %s", out)
	}
}

func TestPosternConfigValidateAcceptsDefault(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test; build cost")
	}

	bin := buildPostern(t)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")

	// Use the binary's own init to produce a default file, then validate it.
	out, err := exec.Command(bin, "config", "init", "--config", cfg).CombinedOutput() //nolint:gosec // test
	require.NoErrorf(t, err, "init failed: %s", out)

	out, err = exec.Command(bin, "config", "validate", "--config", cfg).CombinedOutput() //nolint:gosec // test
	require.NoErrorf(t, err, "validate should accept the freshly-init'd default: %s", out)
}
