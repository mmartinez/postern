package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
)

// twoOpStoreFacts mirrors what the CLI's newProviderFacts derives for a
// config declaring two same-scheme ("op") credstores named personal/team.
func twoOpStoreFacts() config.ProviderFacts {
	return config.ProviderFacts{
		ConfiguredSchemes: map[string]bool{"op": true, "bw": true},
		SchemeNames:       map[string][]string{"op": {"personal", "team"}, "bw": {"bwcorp"}},
		StoreSchemes:      map[string]string{"personal": "op", "team": "op", "bwcorp": "bw"},
		ClassifyRef:       credstore.ParseQualifiedRef,
	}
}

func validateWithFacts(t *testing.T, body string, factsFn config.ProviderFactsFunc) []config.LintError {
	t.Helper()
	cfg, ast, err := config.Load(strings.NewReader(body))
	require.NoError(t, err)
	var lints []config.LintError
	lints = append(lints, config.Validate(cfg, ast)...)
	if factsFn != nil {
		lints = append(lints, config.ValidateProviders(cfg, ast, factsFn(cfg))...)
	}
	return lints
}

func lintMessages(lints []config.LintError) []string {
	out := make([]string, len(lints))
	for i, l := range lints {
		out[i] = l.Error()
	}
	return out
}

const twoOpStoresRule = `
credstores:
  - name: personal
    provider: op-provider
    token: {source: env, env_var: P}
  - name: team
    provider: op-provider
    token: {source: env, env_var: T}
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.anthropic.com
    secret_ref: %s
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

// TestValidateProviders_AmbiguousUnqualifiedRefErrors covers AC (a): the
// error names the ambiguous scheme AND both credstore names.
func TestValidateProviders_AmbiguousUnqualifiedRefErrors(t *testing.T) {
	t.Parallel()

	body := strings.Replace(twoOpStoresRule, "%s", "op://V/I/f", 1)
	facts := func(*config.Config) config.ProviderFacts { return twoOpStoreFacts() }
	msgs := lintMessages(validateWithFacts(t, body, facts))

	var found bool
	for _, m := range msgs {
		if strings.Contains(m, `scheme "op" is ambiguous`) &&
			strings.Contains(m, `"personal"`) && strings.Contains(m, `"team"`) {
			found = true
			require.Regexp(t, `\d+:\d+:`, m, "ambiguity lint must carry a line number")
		}
	}
	require.True(t, found, "expected an ambiguity lint naming scheme and both stores; got %v", msgs)
}

// TestValidateProviders_UnqualifiedRefFineWithSingleStore pins that one
// same-scheme store (and thus every legacy single-credstore config) keeps
// validating clean.
func TestValidateProviders_UnqualifiedRefFineWithSingleStore(t *testing.T) {
	t.Parallel()

	body := strings.Replace(twoOpStoresRule, "%s", "op://V/I/f", 1)
	facts := func(*config.Config) config.ProviderFacts {
		f := twoOpStoreFacts()
		f.SchemeNames = map[string][]string{"op": {"personal"}}
		f.StoreSchemes = map[string]string{"personal": "op"}
		return f
	}
	require.Empty(t, validateWithFacts(t, body, facts))
}

// TestValidateProviders_UnknownQualifiedCredstoreErrors covers AC (b).
func TestValidateProviders_UnknownQualifiedCredstoreErrors(t *testing.T) {
	t.Parallel()

	body := strings.Replace(twoOpStoresRule, "%s", "op+ghost://V/I/f", 1)
	facts := func(*config.Config) config.ProviderFacts { return twoOpStoreFacts() }
	msgs := lintMessages(validateWithFacts(t, body, facts))
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "ghost")
	require.Contains(t, msgs[0], "not configured")
	require.Regexp(t, `\d+:\d+:`, msgs[0])
}

// TestValidateProviders_QualifiedSchemeMismatchErrors covers AC (c): the
// qualifier names a real store but of another vendor/scheme.
func TestValidateProviders_QualifiedSchemeMismatchErrors(t *testing.T) {
	t.Parallel()

	body := strings.Replace(twoOpStoresRule, "%s", "op+bwcorp://V/I/f", 1)
	facts := func(*config.Config) config.ProviderFacts { return twoOpStoreFacts() }
	msgs := lintMessages(validateWithFacts(t, body, facts))
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "bwcorp")
	require.Contains(t, msgs[0], `"bw"`)
	require.Contains(t, msgs[0], `"op"`)
}

// TestValidateProviders_QualifiedRouteAndOAuth1RefsChecked extends the three
// checks to route refs and the oauth1 four refs — every ref a rule can
// resolve.
func TestValidateProviders_QualifiedRouteAndOAuth1RefsChecked(t *testing.T) {
	t.Parallel()

	routesBody := `
credstores:
  - name: personal
    provider: op-provider
    token: {source: env, env_var: P}
  - name: team
    provider: op-provider
    token: {source: env, env_var: T}
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.telegram.org
    routes:
      - name: max
        token: tokMax01tokMax01
        secret_ref: op+ghost://V/max
    inject:
      type: placeholder
      template: "{{ CREDENTIAL }}"
`
	facts := func(*config.Config) config.ProviderFacts { return twoOpStoreFacts() }
	msgs := lintMessages(validateWithFacts(t, routesBody, facts))
	require.Len(t, msgs, 1)
	require.Contains(t, msgs[0], "routes[0].secret_ref")

	oauth1Body := `
credstores:
  - name: personal
    provider: op-provider
    token: {source: env, env_var: P}
  - name: team
    provider: op-provider
    token: {source: env, env_var: T}
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.twitter.com
    inject:
      type: oauth1
      consumer_key_ref: op+ghost://V/ck
      consumer_secret_ref: op+personal://V/cs
      token_ref: op+team://V/tk
      token_secret_ref: op+bwcorp://V/ts
`
	msgs = lintMessages(validateWithFacts(t, oauth1Body, facts))
	paths := make([]string, 0, 2)
	for _, m := range msgs {
		switch {
		case strings.Contains(m, "consumer_key_ref"), strings.Contains(m, "token_secret_ref"):
			paths = append(paths, m)
		default:
			t.Fatalf("unexpected lint %q", m)
		}
	}
	require.Len(t, paths, 2, "unknown-store (consumer_key_ref) and scheme-mismatch (token_secret_ref) refs must both be flagged")
}
