package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/credstore"
)

// fakeOpProvider is a minimal op-scheme provider so a test registry can
// attribute unqualified refs to their sole owning store name.
type fakeOpProvider struct{}

func (fakeOpProvider) Name() string   { return "fake-op" }
func (fakeOpProvider) Scheme() string { return "op" }
func (fakeOpProvider) ShouldCache(string) bool {
	return true
}
func (fakeOpProvider) ValidateSettings(map[string]string) error { return nil }
func (fakeOpProvider) Validate(context.Context, string, map[string]string) error {
	return nil
}

func (fakeOpProvider) NewResolver(context.Context, string, map[string]string) (broker.Resolver, error) {
	return nil, nil
}

const twoStoreRulesConfig = `
credstores:
  - name: personal
    provider: fake-op
    token:
      source: env
      env_var: PERSONAL_TOKEN
  - name: team
    provider: fake-op
    token:
      source: env
      env_var: TEAM_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.anthropic.com
    secret_ref: op+team://Agents/Anthropic/api_key
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
  - host: "*.googleapis.com"
    secret_ref: op+personal://Agents/Google/sa_key
    inject:
      type: header
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
`

func runRulesListWith(t *testing.T, reg *credstore.Registry, args ...string) (string, error) {
	t.Helper()
	cmd := cli.NewRulesCmd(reg)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestRulesList_ShowsCredstoreNamePerRule(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoStoreRulesConfig)
	reg := credstore.NewRegistry()
	reg.Register(fakeOpProvider{})

	out, err := runRulesListWith(t, reg, "list", "--config", path)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 3, "header + two rule rows:\n%s", out)
	require.Contains(t, lines[0], "CREDSTORE")
	// Each row names exactly the store its qualified ref routes to.
	require.Contains(t, lines[1], "op+team://Agents/Anthropic/api_key")
	require.Contains(t, lines[1], "team")
	require.Contains(t, lines[2], "op+personal://Agents/Google/sa_key")
	require.Contains(t, lines[2], "personal")
}

// TestRulesList_UnqualifiedRefShowsSoleOwner covers the unqualified case in a
// single-credstore config.
func TestRulesList_UnqualifiedRefShowsSoleOwner(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoRulesConfig)
	reg := credstore.NewRegistry()
	reg.Register(fakeOpProvider{})

	out, err := runRulesListWith(t, reg, "list", "--config", path)
	require.NoError(t, err)
	require.Contains(t, out, "default", "legacy synthesized default store must be named as the owner")
}

func TestRulesList_JSONShowsCredstores(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoStoreRulesConfig)
	reg := credstore.NewRegistry()
	reg.Register(fakeOpProvider{})

	out, err := runRulesListWith(t, reg, "list", "--config", path, "--format", "json")
	require.NoError(t, err)

	var got []struct {
		Host      string   `json:"host"`
		Credstore []string `json:"credstores"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	require.Equal(t, []string{"team"}, got[0].Credstore)
	require.Equal(t, []string{"personal"}, got[1].Credstore)
}

// TestRulesList_NeverShowsResolvedCredentialValue pins AC 5's second half:
// the credstore column carries NAMES only — no credential material can leak
// into it because nothing here resolves credentials at all.
func TestRulesList_NeverShowsResolvedCredentialValue(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoStoreRulesConfig)
	reg := credstore.NewRegistry()
	reg.Register(fakeOpProvider{})

	tableOut, err := runRulesListWith(t, reg, "list", "--config", path)
	require.NoError(t, err)
	for _, banned := range []string{"client-secret", "Bearer sk-", "resolved"} {
		require.NotContains(t, tableOut, banned)
	}

	jsonOut, err := runRulesListWith(t, reg, "list", "--config", path, "--format", "json")
	require.NoError(t, err)
	for _, banned := range []string{`"credential"`, `"value":"`, `"resolved"`} {
		require.NotContains(t, jsonOut, banned)
	}
}
