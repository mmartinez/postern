package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// placeholderSurfacesConfig is a placeholder-mode rule template the surface
// tests tweak per case. %s is the inject body (name/template/in/max_body_bytes).
const placeholderSurfacesConfig = `
token:
  source: auto
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
%s
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
%s
`

func surfacesYAML(proxyExtra, inject string) string {
	return strings.Replace(strings.Replace(placeholderSurfacesConfig, "%s", proxyExtra, 1), "%s", inject, 1)
}

func TestLoadAndValidate_Surfaces(t *testing.T) {
	t.Parallel()

	cases := []validateCase{
		{
			name: "valid placeholder with body and query surfaces",
			yaml: surfacesYAML("", `      type: placeholder
      name: __tok__
      template: "{{ CREDENTIAL }}"
      in: [body, query]`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "unreserved token over body+query is valid")
			},
		},
		{
			name: "valid per-rule max_body_bytes with body surface",
			yaml: surfacesYAML("", `      type: placeholder
      name: __tok__
      template: "{{ CREDENTIAL }}"
      in: [body]
      max_body_bytes: 4096`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints)
			},
		},
		{
			name: "in with header inject type is rejected",
			yaml: surfacesYAML("", `      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
      in: [body]`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "inject.in is valid only with inject.type=placeholder")
			},
		},
		{
			name: "unknown surface value",
			yaml: surfacesYAML("", `      type: placeholder
      name: __tok__
      template: "{{ CREDENTIAL }}"
      in: [bogus]`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "invalid surface")
			},
		},
		{
			name: "reserved-char token rejected for non-header surface",
			yaml: surfacesYAML("", `      type: placeholder
      name: "key/with/slash"
      template: "{{ CREDENTIAL }}"
      in: [path]`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "unreserved characters")
			},
		},
		{
			name: "reserved-char token allowed for header-only rule",
			yaml: surfacesYAML("", `      type: placeholder
      name: "{weird}"
      template: "{{ CREDENTIAL }}"`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "header-only placeholder keeps the looser token charset")
			},
		},
		{
			name: "negative proxy max_body_bytes",
			yaml: surfacesYAML("  max_body_bytes: -1", `      type: placeholder
      name: __tok__
      template: "{{ CREDENTIAL }}"
      in: [body]`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "max_body_bytes")
			},
		},
		{
			name: "negative per-rule max_body_bytes",
			yaml: surfacesYAML("", `      type: placeholder
      name: __tok__
      template: "{{ CREDENTIAL }}"
      in: [body]
      max_body_bytes: -5`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "max_body_bytes must be >= 0")
			},
		},
		{
			name: "per-rule max_body_bytes without body surface",
			yaml: surfacesYAML("", `      type: placeholder
      name: __tok__
      template: "{{ CREDENTIAL }}"
      in: [query]
      max_body_bytes: 4096`),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "meaningful only when inject.in includes")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, lints, err := config.LoadAndValidate(strings.NewReader(tc.yaml))
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tc.wantLints != nil {
				tc.wantLints(t, lints)
			}
		})
	}
}
