package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// facts mirrors a binary that has the op provider linked in and a config that
// configures only an op credstore: the bw scheme is registered nowhere here,
// so a bw:// rule is unroutable.
func opOnlyFacts(*config.Config) config.ProviderFacts {
	return config.ProviderFacts{
		KnownProviders:    map[string]bool{"op-provider": true},
		ConfiguredSchemes: map[string]bool{"op": true},
	}
}

func TestLoadAndValidateWithProviders_FlagsUnroutableSecretRefScheme(t *testing.T) {
	t.Parallel()

	doc := `
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
`
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), opOnlyFacts)
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "secret_ref") && strings.Contains(lints[i].Message, "bw") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint flagging the unroutable bw scheme; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
	require.Greater(t, found.Line, 0, "registry-aware lint must carry a line number")
}

func TestLoadAndValidateWithProviders_FlagsUnknownProvider(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
credstores:
  - name: main
    provider: nonsense
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), opOnlyFacts)
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "provider") && strings.Contains(lints[i].Message, "nonsense") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint flagging the unknown provider; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
	require.Greater(t, found.Line, 0, "registry-aware lint must carry a line number")
}

// When a provider rejects a credstore's settings, ValidateProviders must
// surface a line-numbered error at credstores[i].settings. The callback
// stands in for the registry-backed ValidateSettings the CLI wires up;
// keeping the provider logic out of the config package preserves the
// brand-agnostic boundary (no config → credstore import).
func TestLoadAndValidateWithProviders_FlagsRejectedSettingsWithLine(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
credstores:
  - name: main
    provider: op
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
    settings:
      bad_key: nope
rules: []
`
	facts := func(*config.Config) config.ProviderFacts {
		return config.ProviderFacts{
			KnownProviders: map[string]bool{"op": true},
			ValidateSettings: func(provider string, settings map[string]string) error {
				if len(settings) > 0 {
					return fmt.Errorf("provider %s: unknown settings key", provider)
				}
				return nil
			},
		}
	}
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), facts)
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "settings") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint flagging the rejected settings; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
	require.Greater(t, found.Line, 0, "settings lint must carry a line number")
}

// A settings map the provider accepts produces no lint, and an empty/absent
// settings block is never rejected (the callback sees a nil/empty map).
func TestLoadAndValidateWithProviders_AcceptsValidSettings(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
credstores:
  - name: main
    provider: op
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
    settings:
      server_url: https://vault.example.com
rules: []
`
	facts := func(*config.Config) config.ProviderFacts {
		return config.ProviderFacts{
			KnownProviders:   map[string]bool{"op": true},
			ValidateSettings: func(_ string, _ map[string]string) error { return nil },
		}
	}
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), facts)
	require.NoError(t, err)
	require.Empty(t, lints, "accepted settings should produce no lints; got %v", lints)
}

func TestLoadAndValidateWithProviders_ValidConfigHasNoProviderLints(t *testing.T) {
	t.Parallel()

	doc := `
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
`
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), opOnlyFacts)
	require.NoError(t, err)
	require.Empty(t, lints, "an op-only config with op rules should produce no lints")
}
