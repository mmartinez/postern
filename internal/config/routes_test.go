package config_test

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// baseRoutesConfig is a valid placeholder-routing config: one host, two named
// routes whose tokens each select a distinct secret. Cases below mutate it.
const baseRoutesConfig = `
token:
  source: auto
  env_var: OP_SERVICE_ACCOUNT_TOKEN
  keychain_account: default
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules:
  - host: api.telegram.org
    inject:
      type: placeholder
      template: "{{ CREDENTIAL }}"
    routes:
      - name: max
        token: tg_max_8Kq2Lp9wZ
        secret_ref: op://Agents/telegram-max/token
      - name: john
        token: tg_john_3Rt7Yx1mQ
        secret_ref: op://Agents/telegram-john/token
`

func TestValidateRoutes(t *testing.T) {
	t.Parallel()

	cases := []validateCase{
		{
			name: "valid routes",
			yaml: baseRoutesConfig,
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "a valid routes block should produce no lints")
			},
		},
		{
			name: "routes and rule-level secret_ref are mutually exclusive",
			yaml: strings.Replace(baseRoutesConfig,
				"  - host: api.telegram.org\n",
				"  - host: api.telegram.org\n    secret_ref: op://V/I/f\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "secret_ref")
			},
		},
		{
			name: "routes with inject.name is rejected",
			yaml: strings.Replace(baseRoutesConfig,
				"      type: placeholder\n",
				"      type: placeholder\n      name: __tok__\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "name")
			},
		},
		{
			name: "routes require placeholder inject type",
			yaml: strings.Replace(baseRoutesConfig,
				"      type: placeholder\n",
				"      type: header\n      name: x-api-key\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "placeholder")
			},
		},
		{
			name: "route with bad secret_ref shape",
			yaml: strings.Replace(baseRoutesConfig,
				"op://Agents/telegram-max/token",
				"not-a-secret-ref",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "secret_ref")
			},
		},
		{
			name: "duplicate route tokens",
			yaml: strings.Replace(baseRoutesConfig,
				"tg_john_3Rt7Yx1mQ",
				"tg_max_8Kq2Lp9wZ",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "duplicate")
			},
		},
		{
			name: "duplicate route names",
			yaml: strings.Replace(baseRoutesConfig,
				"      - name: john\n",
				"      - name: max\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "duplicate route name")
			},
		},
		{
			name: "overlapping route tokens (one a substring of the other)",
			yaml: strings.Replace(baseRoutesConfig,
				"tg_john_3Rt7Yx1mQ",
				"tg_max_8Kq2Lp9wZ_admin",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "overlap")
			},
		},
		{
			name: "empty route name",
			yaml: strings.Replace(baseRoutesConfig,
				"      - name: max\n",
				"      - name: \"\"\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "name")
			},
		},
		{
			name: "empty route token",
			yaml: strings.Replace(baseRoutesConfig,
				"        token: tg_max_8Kq2Lp9wZ\n",
				"        token: \"\"\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "token")
			},
		},
		{
			name: "valid route tokens on body surface",
			yaml: strings.Replace(baseRoutesConfig,
				"      type: placeholder\n",
				"      type: placeholder\n      in: [body]\n",
				1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "unreserved tokens are valid on the body surface")
			},
		},
		{
			name: "route token with reserved chars on non-header surface",
			yaml: strings.Replace(
				strings.Replace(baseRoutesConfig,
					"      type: placeholder\n",
					"      type: placeholder\n      in: [body]\n",
					1),
				"tg_max_8Kq2Lp9wZ", "tg/max/reserved", 1),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "unreserved")
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

// A route token is effectively a shared secret in multi-agent deployments, so
// validator messages that reference a token must fingerprint it, never echo it
// whole (a failing `config validate` can land in CI logs).
func TestValidateRoutes_MasksTokenInMessages(t *testing.T) {
	t.Parallel()

	const token = "tg_max_8Kq2Lp9wZ"
	dup := strings.Replace(baseRoutesConfig, "tg_john_3Rt7Yx1mQ", token, 1)

	_, lints, err := config.LoadAndValidate(strings.NewReader(dup))
	require.NoError(t, err)
	requireLintContains(t, lints, "duplicate")
	for _, l := range lints {
		if strings.Contains(l.Message, token) {
			t.Fatalf("validator message leaked the full token %q: %q", token, l.Message)
		}
	}
}

// A token may contain multi-byte UTF-8 characters on the header surface (where
// the unreserved-charset restriction does not apply). The token fingerprint in
// validator messages must remain valid UTF-8 — never slice mid-rune.
func TestValidateRoutes_MaskTokenStaysValidUTF8(t *testing.T) {
	t.Parallel()

	const tok = "tg_max_café_ünîçødé" // multi-byte; matches the gitleaks test-token allowlist
	cfg := strings.NewReplacer(
		"tg_max_8Kq2Lp9wZ", tok,
		"tg_john_3Rt7Yx1mQ", tok,
	).Replace(baseRoutesConfig)

	_, lints, err := config.LoadAndValidate(strings.NewReader(cfg))
	require.NoError(t, err)
	require.NotEmpty(t, lints, "duplicate multi-byte token should lint")
	for _, l := range lints {
		require.True(t, utf8.ValidString(l.Message), "lint message must be valid UTF-8: %q", l.Message)
	}
}

// A guessable (low-entropy) route token is a non-fatal warning, not an error:
// the operator owns the risk, so the config still loads. High-entropy tokens
// produce no entropy finding, and the warning masks the token.
func TestValidateRoutes_WarnsOnGuessableToken(t *testing.T) {
	t.Parallel()

	// baseRoutesConfig uses long mixed-class tokens — no entropy finding.
	_, lints, err := config.LoadAndValidate(strings.NewReader(baseRoutesConfig))
	require.NoError(t, err)
	for _, l := range lints {
		if strings.Contains(l.Message, "entropy") {
			t.Fatalf("high-entropy tokens should not warn: %v", l)
		}
	}

	// Short, human-named tokens are guessable → warning (not error).
	guessable := strings.NewReplacer(
		"tg_max_8Kq2Lp9wZ", "tgMax",
		"tg_john_3Rt7Yx1mQ", "tgJohn",
	).Replace(baseRoutesConfig)

	_, lints, err = config.LoadAndValidate(strings.NewReader(guessable))
	require.NoError(t, err)
	requireLintContains(t, lints, "entropy")

	var saw bool
	for _, l := range lints {
		if strings.Contains(l.Message, "entropy") {
			saw = true
			require.Equal(t, config.SeverityWarning, l.Severity, "entropy finding must be a warning, not fatal")
			require.NotContains(t, l.Message, "tgMax", "entropy warning must mask the token")
		}
	}
	require.True(t, saw, "expected an entropy warning for a guessable token")
}
