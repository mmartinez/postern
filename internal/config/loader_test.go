package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

func TestLoadFile_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	require.NoError(t, os.WriteFile(path, config.DefaultYAML(), 0o600))

	cfg, lints, err := config.LoadFile(path)
	require.NoError(t, err)
	require.Empty(t, lints)
	require.NotNil(t, cfg)
	require.Equal(t, "127.0.0.1:14321", cfg.Proxy.Listen)
}

func TestLoadFile_NotFound(t *testing.T) {
	t.Parallel()
	_, _, err := config.LoadFile(filepath.Join(t.TempDir(), "absent.yaml"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "open config")
}

func TestLintError_Format(t *testing.T) {
	t.Parallel()

	withLoc := config.LintError{
		Line: 42, Column: 7,
		Severity: config.SeverityError,
		Path:     "rules[0].secret_ref",
		Message:  "bad ref",
	}
	got := withLoc.Error()
	for _, want := range []string{"42", "7", "error", "rules[0].secret_ref", "bad ref"} {
		if !strings.Contains(got, want) {
			t.Errorf("formatted lint missing %q; got %q", want, got)
		}
	}

	noLoc := config.LintError{
		Severity: config.SeverityWarning,
		Path:     "proxy.cache_ttl",
		Message:  "soft hint",
	}
	got = noLoc.Error()
	if !strings.Contains(got, "warning") {
		t.Errorf("expected warning severity; got %q", got)
	}
	if strings.Contains(got, "0:0") {
		t.Errorf("zero-line lint should not print a location; got %q", got)
	}
}

func TestValidate_PlaceholderInjectAcceptsMissingName(t *testing.T) {
	t.Parallel()

	// inject.type=placeholder does not require a header name.
	doc := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: placeholder
      template: "__placeholder__ {{ CREDENTIAL }}"
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.Empty(t, lints)
}

func TestValidate_MissingInjectType(t *testing.T) {
	t.Parallel()
	doc := `
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      template: "{{ CREDENTIAL }}"
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	requireLintContains(t, lints, "inject.type")
}

func TestValidate_BadInjectType(t *testing.T) {
	t.Parallel()
	doc := strings.Replace(validConfig, "type: header", "type: smuggle", 1)
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	requireLintContains(t, lints, "inject.type")
}

func TestValidate_BadOnNoMatch(t *testing.T) {
	t.Parallel()
	doc := strings.Replace(validConfig, "on_no_match: passthrough", "on_no_match: explode", 1)
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	requireLintContains(t, lints, "on_no_match")
}

func TestValidate_NilConfig(t *testing.T) {
	t.Parallel()
	require.Nil(t, config.Validate(nil, nil))
}
