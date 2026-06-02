package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// validateCase pairs an input YAML with expectations on the returned LintError
// slice. Designed for table-driven coverage of every validation rule.
type validateCase struct {
	name      string
	yaml      string
	wantErr   bool                                         // top-level parse/load error
	wantLints func(t *testing.T, lints []config.LintError) // assertions on returned lints
}

const validConfig = `
token:
  source: auto
  env_var: OP_SERVICE_ACCOUNT_TOKEN
  file: ""
  keychain_account: default
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

func TestLoadAndValidate(t *testing.T) {
	t.Parallel()

	cases := []validateCase{
		{
			name: "valid",
			yaml: validConfig,
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "valid config should produce no lints")
			},
		},
		{
			name:    "unknown field at top level",
			yaml:    validConfig + "\nrandom_extra_field: foo\n",
			wantErr: true,
		},
		{
			name: "missing rule host",
			yaml: `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`,
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "host")
			},
		},
		{
			name: "bad secret_ref shape",
			yaml: strings.Replace(validConfig,
				"op://Vault/Item/field",
				"not-a-secret-ref",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "secret_ref")
			},
		},
		{
			name: "valid secret_ref with attribute",
			yaml: strings.Replace(validConfig,
				"op://Vault/Item/field",
				"op://Vault/Item/field?attribute=otp",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "?attribute=otp is allowed")
			},
		},
		{
			name: "duplicate host",
			yaml: `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject: {type: header, name: a, template: "{{ CREDENTIAL }}"}
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject: {type: header, name: b, template: "{{ CREDENTIAL }}"}
`,
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "duplicate")
			},
		},
		{
			name:    "bad cache_ttl duration",
			yaml:    strings.Replace(validConfig, "cache_ttl: 5m", "cache_ttl: not-a-duration", 1),
			wantErr: true, // yaml.v3 will fail to unmarshal into time.Duration
		},
		{
			name: "zero cache_ttl",
			yaml: strings.Replace(validConfig, "cache_ttl: 5m", "cache_ttl: 0s", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "cache_ttl")
			},
		},
		{
			name: "bad listen address",
			yaml: strings.Replace(validConfig, "127.0.0.1:1701", "no-port", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "listen")
			},
		},
		{
			name: "header inject missing name",
			yaml: `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      template: "{{ CREDENTIAL }}"
`,
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "name")
			},
		},
		{
			name: "placeholder inject missing name is fatal",
			yaml: `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: placeholder
      template: "{{ CREDENTIAL }}"
`,
			wantLints: func(t *testing.T, lints []config.LintError) {
				// Fatal: an empty placeholder token matches the empty substring
				// in every header value and smears the credential across every
				// header. Reject at validate time so the proxy never boots (or
				// hot-reloads) into that state.
				requireLintContains(t, lints, "name")
				if !anyOfSeverity(lints, config.SeverityError) {
					t.Errorf("expected severity=error; got %v", lints)
				}
			},
		},
		{
			name: "template missing CREDENTIAL placeholder is fatal",
			yaml: strings.Replace(validConfig,
				`"{{ CREDENTIAL }}"`,
				`"static-value"`,
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				// Fatal: a placeholder-free template fails open (the credential
				// is discarded and the request forwarded unauthenticated), so it
				// must block boot/reload, not just warn.
				if !anyLint(lints, "CREDENTIAL") {
					t.Errorf("expected a CREDENTIAL lint; got %v", lints)
				}
				if !anyOfSeverity(lints, config.SeverityError) {
					t.Errorf("expected severity=error; got %v", lints)
				}
			},
		},
		{
			name: "host glob with two stars",
			yaml: strings.Replace(validConfig, "host: api.example.com", `host: "*.foo.*.com"`, 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "host")
			},
		},
		{
			name: "host glob with leading wildcard ok",
			yaml: strings.Replace(validConfig, "host: api.example.com", `host: "*.googleapis.com"`, 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "single-star prefix glob is allowed")
			},
		},
		{
			name: "default config is valid",
			yaml: string(config.DefaultYAML()),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "the embedded default must validate cleanly")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, lints, err := config.LoadAndValidate(strings.NewReader(tc.yaml))
			if tc.wantErr {
				require.Error(t, err, "expected a parse-level error")
				return
			}
			require.NoError(t, err, "unexpected parse-level error")
			if tc.wantLints != nil {
				tc.wantLints(t, lints)
			}
		})
	}
}

// TestLintErrorIncludesLineNumber covers the acceptance criterion
// "config validate rejects bad rule with line number".
func TestLintErrorIncludesLineNumber(t *testing.T) {
	t.Parallel()

	// Bad secret_ref is on a specific line — confirm we report it.
	doc := `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: this-is-not-an-op-ref
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.NotEmpty(t, lints)

	// secret_ref is the 8th line in the document above (counting the leading newline).
	var found bool
	for _, l := range lints {
		if l.Line > 0 && strings.Contains(l.Message, "secret_ref") {
			found = true
			break
		}
	}
	require.True(t, found, "expected at least one lint with Line > 0 mentioning secret_ref; got %v", lints)
}

// --- helpers ---

func anyLint(lints []config.LintError, substr string) bool {
	for _, l := range lints {
		if strings.Contains(l.Message, substr) {
			return true
		}
	}
	return false
}

func anyOfSeverity(lints []config.LintError, sev config.Severity) bool {
	for _, l := range lints {
		if l.Severity == sev {
			return true
		}
	}
	return false
}

func requireLintContains(t *testing.T, lints []config.LintError, substr string) {
	t.Helper()
	if !anyLint(lints, substr) {
		t.Fatalf("expected a lint mentioning %q; got %v", substr, lints)
	}
}
