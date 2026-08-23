package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/stretchr/testify/require"
)

func writeRoutingConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

// TestBuildCredStoreResolvers_TwoSameSchemeCredstoresHitDifferentResolvers
// asserts the AC: two op credstores with distinct names both boot, keyed by
// NAME, and a qualified ref resolves from the named store — the two
// same-scheme credstores demonstrably hit different resolvers.
func TestBuildCredStoreResolvers_TwoSameSchemeCredstoresHitDifferentResolvers(t *testing.T) {
	t.Parallel()

	reg := credstore.NewRegistry()
	pp := &plainProvider{scheme: "op"}
	reg.Register(pp)

	stores := []config.CredStore{
		{Name: "personal", Provider: pp.Name(), Token: keychainToken("primary")},
		{Name: "team", Provider: pp.Name(), Token: keychainToken("secondary")},
	}

	resolvers, err := buildCredStoreResolvers(context.Background(), reg, stores, seededStore(t), discardLogger(), nil)
	require.NoError(t, err, "two same-scheme credstores must boot under name-keyed routing")
	require.Len(t, resolvers, 2)

	owners := buildSchemeOwners(reg, stores)
	require.Equal(t, map[string][]string{"op": {"personal", "team"}}, owners)

	router, err := credstore.NewNameRouter(resolvers, owners)
	require.NoError(t, err)

	vPersonal, err := router.Resolve(context.Background(), "", "op+personal://Vault/Item/field")
	require.NoError(t, err)
	vTeam, err := router.Resolve(context.Background(), "", "op+team://Agents/Anthropic/api_key")
	require.NoError(t, err)

	// plainProvider.NewResolver binds the store's token into the resolver,
	// so different returned values prove the qualified refs hit the two
	// DIFFERENT per-store resolvers.
	require.Equal(t, "client-secret-val", vPersonal)
	require.NotEqual(t, vPersonal, vTeam)
}

// TestAssertRulesRoutable_AmbiguousUnqualifiedRefErrors asserts fail-closed
// boot semantics for an unqualified ref while two same-scheme credstores are
// configured.
func TestAssertRulesRoutable_AmbiguousUnqualifiedRefErrors(t *testing.T) {
	t.Parallel()

	resolvers := map[string]broker.Resolver{
		"personal": stubResolver{val: "a"},
		"team":     stubResolver{val: "b"},
	}
	owners := map[string][]string{"op": {"personal", "team"}}

	err := assertRulesRoutable([]broker.Rule{{Host: "api.example.com", SecretRef: "op://V/I/f"}}, resolvers, owners)
	require.Error(t, err)
	require.Contains(t, err.Error(), `"personal"`)
	require.Contains(t, err.Error(), `"team"`)
	require.Contains(t, err.Error(), `"op"`)

	// A fully qualified ruleset boots cleanly against the same two stores.
	okRules := []broker.Rule{{
		Host:      "api.anthropic.com",
		SecretRef: "op+team://V/I/f",
		Routes: []broker.Route{
			{Name: "max", Token: "tokMax01", SecretRef: "op+personal://V/max"},
		},
	}}
	require.NoError(t, assertRulesRoutable(okRules, resolvers, owners))
}

// TestAssertRulesRoutable_UnknownQualifiedCredstoreErrors keeps a typo'd
// qualifier from surviving to the first request.
func TestAssertRulesRoutable_UnknownQualifiedCredstoreErrors(t *testing.T) {
	t.Parallel()

	resolvers := map[string]broker.Resolver{"personal": stubResolver{val: "a"}}
	err := assertRulesRoutable(
		[]broker.Rule{{Host: "api.example.com", SecretRef: "op+tream://V/I/f"}},
		resolvers,
		map[string][]string{"op": {"personal"}},
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "tream")
}

func opOnlyRegistry() *credstore.Registry {
	reg := credstore.NewRegistry()
	reg.Register(&plainProvider{scheme: "op"})
	return reg
}

const ambiguousConfig = `
credstores:
  - name: personal
    provider: plain-op
    token:
      source: env
      env_var: PERSONAL_TOKEN
  - name: team
    provider: plain-op
    token:
      source: env
      env_var: TEAM_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.anthropic.com
    secret_ref: op://Agents/Anthropic/api_key
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`

// TestConfigValidate_AmbiguousUnqualifiedRefIsLineNumbered runs the real
// `postern config validate` command end-to-end: an unqualified op:// ref
// while two op credstores are declared must produce a line-numbered error
// naming the ambiguous scheme and BOTH credstore names.
func TestConfigValidate_AmbiguousUnqualifiedRefIsLineNumbered(t *testing.T) {
	t.Parallel()

	path := writeRoutingConfig(t, ambiguousConfig)

	var out bytes.Buffer
	cmd := NewConfigCmd(opOnlyRegistry())
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"validate", "--config", path})
	err := cmd.Execute()

	require.Error(t, err)
	s := out.String()
	require.Contains(t, s, "rules[0].secret_ref")
	require.Contains(t, s, `"op"`)
	require.Contains(t, s, `"personal"`)
	require.Contains(t, s, `"team"`)
	require.Regexp(t, `\d+:\d+: error`, s, "error must carry a line:column location")
}

// TestConfigValidate_QualifiedRefWithTwoStoresValidates pins the happy path:
// the same two-store config with every ref qualified validates clean.
func TestConfigValidate_QualifiedRefWithTwoStoresValidates(t *testing.T) {
	t.Parallel()

	path := writeRoutingConfig(t, strings.Replace(
		ambiguousConfig, "op://Agents/Anthropic/api_key", "op+team://Agents/Anthropic/api_key", 1,
	))

	var out bytes.Buffer
	cmd := NewConfigCmd(opOnlyRegistry())
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"validate", "--config", path})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "ok")
}

// TestConfigValidate_LegacyTokenFormStillValidates pins AC 3: the legacy
// top-level token: form loads and validates unchanged alongside the new
// checks.
func TestConfigValidate_LegacyTokenFormStillValidates(t *testing.T) {
	t.Parallel()

	path := writeRoutingConfig(t, `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.anthropic.com
    secret_ref: op://Agents/Anthropic/api_key
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`)

	var out bytes.Buffer
	cmd := NewConfigCmd(opOnlyRegistry())
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"validate", "--config", path})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "ok")
}
