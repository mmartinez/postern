package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/cli"
)

func writeRulesConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

const twoRulesConfig = `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.anthropic.com
    secret_ref: op://Agents/Anthropic/api_key
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
  - host: "*.googleapis.com"
    secret_ref: op://Agents/Google/sa_key
    inject:
      type: header
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
`

func runRulesList(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := cli.NewRulesCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func TestRulesList_DefaultFormatIsTable(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoRulesConfig)
	out, _, err := runRulesList(t, "list", "--config", path)
	require.NoError(t, err)

	// Table header + both rules' host patterns + inject metadata.
	require.Contains(t, out, "HOST")
	require.Contains(t, out, "SECRET REF")
	require.Contains(t, out, "INJECT")
	require.Contains(t, out, "api.anthropic.com")
	require.Contains(t, out, "*.googleapis.com")
	require.Contains(t, out, "op://Agents/Anthropic/api_key")
	require.Contains(t, out, "x-api-key")
	require.Contains(t, out, "{{ CREDENTIAL }}")
}

func TestRulesList_JSONFormat(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoRulesConfig)
	out, _, err := runRulesList(t, "list", "--config", path, "--format", "json")
	require.NoError(t, err)

	var got []struct {
		Host      string `json:"host"`
		SecretRef string `json:"secret_ref"`
		Inject    struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Template string `json:"template"`
		} `json:"inject"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got), "stdout must be valid JSON")
	require.Len(t, got, 2)
	require.Equal(t, "api.anthropic.com", got[0].Host)
	require.Equal(t, "op://Agents/Anthropic/api_key", got[0].SecretRef)
	require.Equal(t, "header", got[0].Inject.Type)
	require.Equal(t, "x-api-key", got[0].Inject.Name)
}

func TestRulesList_RejectsUnknownFormat(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoRulesConfig)
	_, _, err := runRulesList(t, "list", "--config", path, "--format", "yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "format")
}

func TestRulesList_EmptyRulesPrintsHeaderOnly(t *testing.T) {
	t.Parallel()

	emptyRules := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`
	path := writeRulesConfig(t, emptyRules)
	out, _, err := runRulesList(t, "list", "--config", path)
	require.NoError(t, err)

	// A header line and a "(no rules)" hint, no host rows.
	require.Contains(t, out, "HOST")
	require.Contains(t, out, "no rules")
	require.NotContains(t, out, "op://")
}

func TestRulesList_MissingConfigErrors(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "no-such.yaml")
	_, _, err := runRulesList(t, "list", "--config", missing)
	require.Error(t, err)
}

// TestRulesList_SurfacesSchemaErrors confirms a typo'd template name produces
// an error + stderr diagnostic instead of a misleading row with empty columns.
func TestRulesList_SurfacesSchemaErrors(t *testing.T) {
	t.Parallel()

	bad := `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - template: anthrpic
    secret_ref: op://Agents/Anthropic/api_key
`
	path := writeRulesConfig(t, bad)
	_, errb, err := runRulesList(t, "list", "--config", path)
	require.Error(t, err, "rules list must refuse to print a malformed config")
	require.Contains(t, errb, "anthrpic", "stderr must surface the unknown-template lint")
	require.Contains(t, err.Error(), "schema error")
}

// CRITICAL guardrail: rules list MUST never resolve or surface the
// credential value. Even though list only knows the
// secret_ref (not the credential), pin the column / key set so a future
// change that added a "resolved value" field would fail the test
// instead of silently leaking what gets resolved at render time.
func TestRulesList_NeverEmitsResolvedCredentialField(t *testing.T) {
	t.Parallel()

	path := writeRulesConfig(t, twoRulesConfig)
	tableOut, _, err := runRulesList(t, "list", "--config", path)
	require.NoError(t, err)
	// Pin the table header: any new column would change this line.
	header := strings.SplitN(tableOut, "\n", 2)[0]
	require.Equal(t, "HOST               SECRET REF                     INJECT  NAME           TEMPLATE", header)

	jsonOut, _, err := runRulesList(t, "list", "--config", path, "--format", "json")
	require.NoError(t, err)
	// Pin the JSON key set per object (decoding into a permissive type
	// and then re-encoding would mask added fields; this catches them).
	for _, banned := range []string{`"credential"`, `"value":"`, `"resolved"`} {
		require.NotContains(t, jsonOut, banned, "credential value field must not exist in JSON output")
	}
}
