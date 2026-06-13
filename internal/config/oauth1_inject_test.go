package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// oauth1Head is the credstore + proxy preamble for the oauth1 rule fixtures; the
// op credstore just satisfies routing (the validator does not check provider
// names against the registry).
const oauth1Head = `
credstores:
  - name: vault
    provider: op
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
`

func TestOAuth1_ValidRuleLintsClean(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(oauth1Head + `
  - host: api.example.com
    inject:
      type: oauth1
      consumer_key_ref: op://Vault/x/consumer_key
      consumer_secret_ref: op://Vault/x/consumer_secret
      token_ref: op://Vault/x/token
      token_secret_ref: op://Vault/x/token_secret
`))
	require.NoError(t, err)
	require.Empty(t, lints, "valid oauth1 rule should lint clean; got %v", lints)
}

func TestOAuth1_MissingRefIsError(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(oauth1Head + `
  - host: api.example.com
    inject:
      type: oauth1
      consumer_key_ref: op://Vault/x/consumer_key
      consumer_secret_ref: op://Vault/x/consumer_secret
      token_ref: op://Vault/x/token
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "token_secret_ref is required")
}

func TestOAuth1_RuleLevelSecretRefIsError(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(oauth1Head + `
  - host: api.example.com
    secret_ref: op://Vault/x/whatever
    inject:
      type: oauth1
      consumer_key_ref: op://Vault/x/consumer_key
      consumer_secret_ref: op://Vault/x/consumer_secret
      token_ref: op://Vault/x/token
      token_secret_ref: op://Vault/x/token_secret
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "secret_ref must be empty")
}

func TestOAuth1_HeaderFieldsAreError(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(oauth1Head + `
  - host: api.example.com
    inject:
      type: oauth1
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
      consumer_key_ref: op://Vault/x/consumer_key
      consumer_secret_ref: op://Vault/x/consumer_secret
      token_ref: op://Vault/x/token
      token_secret_ref: op://Vault/x/token_secret
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "not used with inject.type=oauth1")
}

func TestOAuth1_RefsOnHeaderRuleAreError(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(oauth1Head + `
  - host: api.example.com
    secret_ref: op://Vault/x/key
    inject:
      type: header
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
      consumer_key_ref: op://Vault/x/consumer_key
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "valid only with inject.type=oauth1")
}

func TestOAuth1_MalformedRefIsError(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(oauth1Head + `
  - host: api.example.com
    inject:
      type: oauth1
      consumer_key_ref: not-a-uri
      consumer_secret_ref: op://Vault/x/consumer_secret
      token_ref: op://Vault/x/token
      token_secret_ref: op://Vault/x/token_secret
`))
	require.NoError(t, err)
	requireLintContains(t, lints, "must be a URI")
}
