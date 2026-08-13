package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// baseInjectsConfig is a valid multi-header config: one host, one secret_ref,
// two header injections fed by that single secret. It mirrors an upstream that
// authenticates the same key through two different headers depending on which
// endpoint the agent calls. Cases below mutate it.
const baseInjectsConfig = `
token:
  source: auto
  env_var: OP_SERVICE_ACCOUNT_TOKEN
  keychain_account: default
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.example.com
    secret_ref: op://Agents/example/api_key
    injects:
      - type: header
        name: authorization
        template: "Bearer {{ CREDENTIAL }}"
      - type: header
        name: x-api-key
        template: "{{ CREDENTIAL }}"
`

func TestValidateInjects(t *testing.T) {
	t.Parallel()

	cases := []validateCase{
		{
			name: "valid injects",
			yaml: baseInjectsConfig,
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "a valid injects block should produce no lints")
			},
		},
		{
			name: "injects and inject are mutually exclusive",
			yaml: strings.Replace(baseInjectsConfig,
				"    injects:\n",
				"    inject:\n      type: header\n      name: x-api-key\n      template: \"{{ CREDENTIAL }}\"\n    injects:\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "mutually exclusive")
			},
		},
		{
			name: "injects and routes are mutually exclusive",
			yaml: baseInjectsConfig + `    routes:
      - name: max
        token: tg_max_8Kq2Lp9wZ
        secret_ref: op://Agents/example-max/token
`,
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "mutually exclusive")
			},
		},
		{
			name: "injects and a preset template are mutually exclusive",
			yaml: strings.Replace(baseInjectsConfig,
				"  - host: api.example.com\n",
				"  - template: anthropic\n    host: api.example.com\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "template")
			},
		},
		{
			name: "injects requires a rule-level secret_ref",
			yaml: strings.Replace(baseInjectsConfig,
				"    secret_ref: op://Agents/example/api_key\n", "", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "secret_ref is required")
			},
		},
		{
			name: "injects rejects a malformed secret_ref",
			yaml: strings.Replace(baseInjectsConfig,
				"op://Agents/example/api_key", "not-a-secret-ref", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "secret_ref")
			},
		},
		{
			name: "injects entry must be type header",
			yaml: strings.Replace(baseInjectsConfig,
				"      - type: header\n        name: x-api-key\n",
				"      - type: placeholder\n        name: __tok__\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "type: header")
			},
		},
		{
			name: "injects entry with an empty name",
			yaml: strings.Replace(baseInjectsConfig,
				"        name: x-api-key\n", "        name: \"\"\n", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "name is required")
			},
		},
		{
			name: "injects entry with an empty template",
			yaml: strings.Replace(baseInjectsConfig,
				"        template: \"{{ CREDENTIAL }}\"\n", "        template: \"\"\n", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "template is required")
			},
		},
		{
			name: "injects entry template without the CREDENTIAL placeholder",
			yaml: strings.Replace(baseInjectsConfig,
				"        template: \"{{ CREDENTIAL }}\"\n", "        template: \"static\"\n", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "{{ CREDENTIAL }}")
			},
		},
		{
			name: "duplicate header names, differing only in case",
			yaml: strings.Replace(baseInjectsConfig,
				"        name: x-api-key\n", "        name: Authorization\n", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "duplicate header name")
			},
		},
		{
			name: "injects entry carrying a placeholder-only field",
			yaml: strings.Replace(baseInjectsConfig,
				"        template: \"{{ CREDENTIAL }}\"\n",
				"        template: \"{{ CREDENTIAL }}\"\n        in: [body]\n", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "only type, name, and template")
			},
		},
		{
			name: "empty injects list",
			yaml: strings.Replace(baseInjectsConfig,
				`    injects:
      - type: header
        name: authorization
        template: "Bearer {{ CREDENTIAL }}"
      - type: header
        name: x-api-key
        template: "{{ CREDENTIAL }}"
`,
				"    injects: []\n", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "at least one entry")
			},
		},
		{
			name: "unknown field inside an injects entry",
			yaml: strings.Replace(baseInjectsConfig,
				"        name: x-api-key\n", "        nope: x-api-key\n", 1),
			wantErr: true,
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
