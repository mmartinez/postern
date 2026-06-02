package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/credstore"
)

func runConfigValidate(t *testing.T, path string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := cli.NewConfigCmd(credstore.Default())
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{"validate", "--config", path})
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func writeValidateConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

// `config validate` must run the registry-aware pass, not just schema lints:
// a rule whose secret_ref scheme no configured credstore can resolve is an
// error caught here rather than at server boot. Routability keys on the
// config's credstores, not on which providers the binary links: the legacy
// token block yields an op-only credstore, so the bw:// rule has no configured
// credstore to resolve it even though the bw provider is registered.
func TestConfigValidate_FlagsUnroutableSecretRefScheme(t *testing.T) {
	t.Parallel()

	path := writeValidateConfig(t, `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: bw://Collection/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`)

	stdout, _, err := runConfigValidate(t, path)
	require.Error(t, err, "validate must fail on an unroutable secret_ref scheme")
	require.Contains(t, stdout, "bw", "the reported lint should name the unroutable scheme")
}

// `config validate` must reject a `settings:` block the configured provider
// does not recognize, with a line number, rather than silently ignoring it.
// The default build's only provider recognizes no settings keys, so any
// settings block on it is an error. The provider name is read from the
// registry (not hard-coded) to keep this file free of vendor brand literals.
func TestConfigValidate_FlagsUnsupportedSettings(t *testing.T) {
	t.Parallel()

	p, ok := credstore.ForScheme("op")
	require.True(t, ok, "the op provider must be registered in the default build")

	body := fmt.Sprintf(`
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
credstores:
  - name: main
    provider: %s
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
    settings:
      server_url: https://example.com
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`, p.Name())
	path := writeValidateConfig(t, body)

	stdout, _, err := runConfigValidate(t, path)
	require.Error(t, err, "validate must fail when a settings block is set on a provider that recognizes none")
	require.Contains(t, stdout, "settings", "the reported lint should mention settings")
}

// The default binary links the bw provider, so a config selecting it validates
// clean: the provider is known, its bw scheme is routable, and a well-formed
// settings block is accepted. (A config naming an unregistered provider fails
// validate with "unknown provider".) The provider name is read from the
// registry to keep this file free of vendor brand literals.
func TestConfigValidate_AcceptsBwProvider(t *testing.T) {
	t.Parallel()

	p, ok := credstore.ForScheme("bw")
	require.True(t, ok, "the bw provider must be registered in the default build")

	body := fmt.Sprintf(`
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
credstores:
  - name: bw-prod
    provider: %s
    token:
      source: env
      env_var: BWS_ACCESS_TOKEN
    settings:
      server_url: https://vault.example.com
rules:
  - host: api.example.com
    secret_ref: bw://e92f4f1a-0c3d-4b2a-9f1e-2a3b4c5d6e7f
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`, p.Name())
	path := writeValidateConfig(t, body)

	_, _, err := runConfigValidate(t, path)
	require.NoError(t, err, "a bw credstore with a routable bw:// rule and valid settings should validate clean")
}

// A config whose rule scheme matches a configured credstore validates clean.
func TestConfigValidate_AcceptsRoutableConfig(t *testing.T) {
	t.Parallel()

	path := writeValidateConfig(t, `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`)

	_, _, err := runConfigValidate(t, path)
	require.NoError(t, err, "an op rule against an op credstore should validate clean")
}
