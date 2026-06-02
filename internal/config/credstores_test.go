package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// Fixtures below use `provider: op` purely because the validator
// intentionally does NOT check provider names against the credstore
// registry (config cannot import credstore — see the import-cycle note
// in MEMORY.md). Any non-empty string passes; "op" is convenient.
// Production configs need the registered Provider.Name(); see
// docs/providers.md for a worked example.

// A legacy config with a top-level `token:` block and no `credstores:`
// list should still load. The loader synthesizes a single "default"
// credstore from the legacy token field so the rest of the runtime can
// always iterate over a non-empty CredStores slice. The synthesized
// credstore leaves Provider empty so the runtime (which has registry
// access) picks the canonical provider; the config package stays
// brand-agnostic.
func TestLoadAndValidate_LegacyTokenSynthesizesDefaultCredStore(t *testing.T) {
	t.Parallel()

	cfg, lints, err := config.LoadAndValidate(strings.NewReader(`
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
`))
	require.NoError(t, err)
	require.Empty(t, lints, "legacy form should lint clean; got %v", lints)
	require.Len(t, cfg.CredStores, 1)
	require.Equal(t, config.DefaultCredStoreName, cfg.CredStores[0].Name)
	require.Equal(t, "", cfg.CredStores[0].Provider, "synthesized default leaves provider blank so the cli registry picks it")
	require.Equal(t, config.TokenSourceEnv, cfg.CredStores[0].Token.Source)
	require.True(t, cfg.Token.IsZero(), "legacy token field should be folded into the credstore")
}

// A config that sets BOTH the legacy `token:` block and the new
// `credstores:` list is ambiguous: which credstore owns the legacy
// token field? Reject it with a clear lint.
func TestLoadAndValidate_TokenAndCredStoresIsAnError(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
credstores:
  - name: primary
    provider: op
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "credstores")
}

func TestLoadAndValidate_MultiCredStoreParses(t *testing.T) {
	t.Parallel()

	cfg, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: primary
    provider: op
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
`))
	require.NoError(t, err)
	require.Empty(t, lints)
	require.Len(t, cfg.CredStores, 1)
	require.Equal(t, "primary", cfg.CredStores[0].Name)
}

func TestLoadAndValidate_DuplicateCredStoreNameIsAnError(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: dup
    provider: op
    token:
      source: env
      env_var: A
  - name: dup
    provider: op
    token:
      source: env
      env_var: B
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "duplicate credstore name")
}

func TestLoadAndValidate_EmptyProviderIsAnError(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: oops
    provider: ""
    token:
      source: env
      env_var: A
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "provider is required")
}

func TestLoadAndValidate_EmptyCredStoreNameIsAnError(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: ""
    provider: op
    token:
      source: env
      env_var: A
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "name is required")
}

// A credstore may carry an optional, provider-interpreted `settings:` map
// (e.g. a self-hosted server URL). The strict-YAML loader
// (KnownFields(true)) must accept `settings` as a known field and round-trip
// the map verbatim; per-key validation is the provider's job, not the
// schema's. Existing configs without `settings` are unaffected.
func TestLoadAndValidate_CredStoreSettingsRoundTrip(t *testing.T) {
	t.Parallel()

	cfg, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: bw-prod
    provider: bitwarden
    token:
      source: env
      env_var: BWS_ACCESS_TOKEN
    settings:
      server_url: https://vault.example.com
      bws_path: /usr/local/bin/bws
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	require.Empty(t, lints, "settings block should parse cleanly; got %v", lints)
	require.Len(t, cfg.CredStores, 1)
	require.Equal(t, map[string]string{
		"server_url": "https://vault.example.com",
		"bws_path":   "/usr/local/bin/bws",
	}, cfg.CredStores[0].Settings)
}

// A rule with a non-op scheme must validate cleanly. The secret_ref
// grammar is intentionally scheme-agnostic at the config layer; per-vendor
// grammar is the provider's responsibility (a future Bitwarden-format
// check lives in the bw provider, not here).
func TestValidate_AcceptsNonOpSchemes(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: bw
    provider: bitwarden
    token:
      source: env
      env_var: BW_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: bw://collection/item/field
    inject:
      type: header
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
`))
	require.NoError(t, err)
	require.Empty(t, lints, "bw:// refs should validate cleanly; got %v", lints)
}

// A user who hand-authors `credstores: [{name: default}]` (no provider)
// must NOT bypass validation. The synthesized-default marker that the
// loader sets is invisible to the YAML decoder, so the validator can
// tell user-authored entries apart from synthesized ones.
func TestValidate_UserAuthoredDefaultRequiresProvider(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: default
    token:
      source: env
      env_var: A
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "provider is required")
}

// Duplicate user-authored credstores with the name "default" must also
// produce a duplicate-name lint; the synthesized-default exemption is
// loader-only.
func TestValidate_UserAuthoredDuplicateDefaultIsAnError(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: default
    provider: op
    token:
      source: env
      env_var: A
  - name: default
    provider: op
    token:
      source: env
      env_var: B
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "duplicate credstore name")
}

// A config with rules but no credstores (and no legacy token: block) must
// produce a clear lint, not crash at server boot with the low-level
// "scheme router requires at least one resolver" error.
func TestValidate_RulesRequireCredStores(t *testing.T) {
	t.Parallel()

	_, lints, err := config.LoadAndValidate(strings.NewReader(`
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
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "credstores")
}
