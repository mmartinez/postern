package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// A routable env: block (every value resolves to a configured scheme) produces
// no lints — the same brand-agnostic scheme check that guards rule secret_refs
// applies to the values `postern exec` injects as environment variables.
func TestValidate_EnvBlock_AcceptsRoutableRefs(t *testing.T) {
	t.Parallel()

	doc := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
env:
  DATABASE_URL: op://Infra/db/url
  STRIPE_KEY: op://Infra/stripe/secret
rules: []
`
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), opOnlyFacts)
	require.NoError(t, err)
	require.Empty(t, lints, "routable env refs should produce no lints; got %v", lints)
}

// An env value whose scheme no configured credstore resolves can never be
// injected; flag it at validate time with a line number rather than at exec.
func TestValidate_EnvBlock_FlagsUnroutableScheme(t *testing.T) {
	t.Parallel()

	doc := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
env:
  DATABASE_URL: bw://Coll/db/url
rules: []
`
	_, lints, err := config.LoadAndValidateWithProviders(strings.NewReader(doc), opOnlyFacts)
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "env.DATABASE_URL") && strings.Contains(lints[i].Message, "bw") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint flagging the unroutable bw scheme; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
	require.Greater(t, found.Line, 0, "registry-aware env lint must carry a line number")
}

// A value that isn't a <scheme>://<rest> URI is a schema error, surfaced
// without needing the registry facts.
func TestValidate_EnvBlock_FlagsMalformedRef(t *testing.T) {
	t.Parallel()

	doc := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
env:
  DATABASE_URL: not-a-uri
rules: []
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "env.DATABASE_URL") && strings.Contains(lints[i].Message, "URI") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint flagging the malformed env value; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
}

// A key that isn't a valid environment-variable name is a schema error: it
// could never be exported to the child process.
func TestValidate_EnvBlock_FlagsInvalidVarName(t *testing.T) {
	t.Parallel()

	doc := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
env:
  "bad-name": op://Infra/db/url
rules: []
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "env") && strings.Contains(lints[i].Message, "environment variable name") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint flagging the invalid env var name; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
}

// An env: block with no credstore to resolve against can never inject anything;
// mirror the rules-need-a-credstore guard so the failure is a line-friendly
// lint rather than a cryptic boot error.
func TestValidate_EnvBlock_RequiresCredStore(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
env:
  DATABASE_URL: op://Infra/db/url
rules: []
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)

	var found *config.LintError
	for i := range lints {
		if strings.Contains(lints[i].Path, "credstores") && strings.Contains(lints[i].Message, "env") {
			found = &lints[i]
		}
	}
	require.NotNil(t, found, "want a lint requiring a credstore when env is set; got %v", lints)
	require.Equal(t, config.SeverityError, found.Severity)
}
