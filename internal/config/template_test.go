package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// TestTemplate_ExpandsBuiltinDefaults covers the headline user story for
// templates: a rule that names a built-in template only needs a secret_ref;
// host and inject defaults come from the registry.
func TestTemplate_ExpandsBuiltinDefaults(t *testing.T) {
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
  - template: anthropic
    secret_ref: op://Agents/Anthropic/api_key
`
	cfg, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.Empty(t, lints)
	require.Len(t, cfg.Rules, 1)

	r := cfg.Rules[0]
	require.Equal(t, "anthropic", r.Template)
	require.Equal(t, "api.anthropic.com", r.Host)
	require.Equal(t, config.InjectTypeHeader, r.Inject.Type)
	require.Equal(t, "x-api-key", r.Inject.Name)
	require.Equal(t, "{{ CREDENTIAL }}", r.Inject.Template)
}

// TestTemplate_UserFieldsOverrideRegistry covers the override path: a user
// who picks the openai template but wants a non-standard header name or
// credential format gets exactly that; the template defaults only fill in
// fields the user left blank.
func TestTemplate_UserFieldsOverrideRegistry(t *testing.T) {
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
  - template: openai
    host: my.openai.proxy.local
    secret_ref: op://Agents/OpenAI/api_key
    inject:
      template: "Token {{ CREDENTIAL }}"
`
	cfg, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.Empty(t, lints, "user overrides on a template must not lint")
	require.Len(t, cfg.Rules, 1)

	r := cfg.Rules[0]
	require.Equal(t, "my.openai.proxy.local", r.Host, "user host overrides template host")
	require.Equal(t, config.InjectTypeHeader, r.Inject.Type, "template fills type")
	require.Equal(t, "authorization", r.Inject.Name, "template fills name when user omits it")
	require.Equal(t, "Token {{ CREDENTIAL }}", r.Inject.Template, "user template wins")
}

// TestTemplate_UnknownNameIsLintError surfaces a typo in a template name as
// a fatal lint pinned to the rules[i].template line.
func TestTemplate_UnknownNameIsLintError(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - template: anthropik
    secret_ref: op://Agents/Anthropic/api_key
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.NotEmpty(t, lints)

	var found bool
	for _, l := range lints {
		if strings.HasSuffix(l.Path, "].template") && strings.Contains(l.Message, "anthropik") {
			require.Equal(t, config.SeverityError, l.Severity)
			require.Positive(t, l.Line, "unknown-template lint must carry a line number")
			found = true
		}
	}
	require.True(t, found, "expected an unknown-template lint; got %v", lints)
}

// TestTemplate_StillRequiresSecretRef confirms expansion does not paper over
// a missing secret_ref. The template carries host + inject defaults but the
// secret reference is intentionally per-rule.
func TestTemplate_StillRequiresSecretRef(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - template: anthropic
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.NotEmpty(t, lints)

	var found bool
	for _, l := range lints {
		if strings.Contains(l.Path, "secret_ref") {
			found = true
		}
	}
	require.True(t, found, "missing secret_ref must still lint when template is set; got %v", lints)
}

// TestTemplate_UnknownNameSuppressesCascade ensures a single typo'd template
// name produces exactly one fatal lint pointing at the template line — not a
// pile of misleading 'host is required' / 'inject.type is required' lints
// for fields the user intentionally omitted.
func TestTemplate_UnknownNameSuppressesCascade(t *testing.T) {
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
  - template: anthrpic
    secret_ref: op://Agents/Anthropic/api_key
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)

	var fatals []config.LintError
	for _, l := range lints {
		if l.Severity == config.SeverityError {
			fatals = append(fatals, l)
		}
	}
	require.Len(t, fatals, 1, "exactly one fatal lint for an unknown template; got %v", lints)
	require.Contains(t, fatals[0].Path, "].template")
	require.Positive(t, fatals[0].Line, "the one lint must carry a line number")
}

// TestTemplate_UnknownNameMentionsValidNames helps users by listing the
// registered template names in the error message.
func TestTemplate_UnknownNameMentionsValidNames(t *testing.T) {
	t.Parallel()

	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - template: nope
    secret_ref: op://Vault/Item/field
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)

	var msg string
	for _, l := range lints {
		if strings.HasSuffix(l.Path, "].template") {
			msg = l.Message
		}
	}
	require.Contains(t, msg, "anthropic", "error message should enumerate known names so users can find their typo")
}
