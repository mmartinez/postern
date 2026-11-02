package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// approvalRuleConfig wraps one header rule around approvalLine, which sits
// on line 12 of the document.
func approvalRuleConfig(approvalLine string) string {
	return `
credstores:
  - name: default
    provider: op
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
` + approvalLine + "\n"
}

func TestCheckApproval(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		approval string
		goos     string
		wantMsg  string // empty means no approval lint
	}{
		{name: "empty mapping on linux", approval: "    approval: {}", goos: "linux"},
		{name: "absent block", approval: "", goos: "darwin"},
		{
			name:     "null block",
			approval: "    approval:",
			goos:     "linux",
			wantMsg:  "approval needs a mapping; use approval: {} to prompt on every request",
		},
		{
			name:     "explicit null block",
			approval: "    approval: null",
			goos:     "linux",
			wantMsg:  "approval needs a mapping; use approval: {} to prompt on every request",
		},
		{
			name:     "unsupported platform",
			approval: "    approval: {}",
			goos:     "windows",
			wantMsg:  "approval is not supported on windows",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, root, err := Load(strings.NewReader(approvalRuleConfig(tc.approval)))
			require.NoError(t, err)
			v := newValidator(root)
			v.goos = tc.goos
			v.checkApproval("rules[0]", cfg.Rules[0])

			if tc.wantMsg == "" {
				require.Empty(t, v.out)
				return
			}
			require.Len(t, v.out, 1)
			got := v.out[0]
			require.Equal(t, tc.wantMsg, got.Message)
			require.Equal(t, SeverityError, got.Severity)
			require.Equal(t, 12, got.Line, "lint must point at the approval line")
		})
	}
}

// TestCheckApproval_NullThroughAliasOrMerge covers an approval value that
// reaches the rule through an alias or a merge key. It decodes to nil like a
// literal null, so it must be rejected the same way.
func TestCheckApproval_NullThroughAliasOrMerge(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		doc      string
		wantLine int
	}{
		{
			name:     "alias",
			doc:      approvalRuleConfig("    paths: &off null\n    approval: *off"),
			wantLine: 13,
		},
		{
			name: "merge key",
			doc: `
credstores:
  - name: default
    provider: op
    settings: &extra
      approval: null
rules:
  - <<: *extra
    host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`,
			wantLine: 6,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, root, err := Load(strings.NewReader(tc.doc))
			require.NoError(t, err)
			require.Nil(t, cfg.Rules[0].Approval)

			lints := Validate(cfg, root)
			var found bool
			for _, l := range lints {
				if l.Path == "rules[0].approval" && l.Severity == SeverityError {
					require.Equal(t, tc.wantLine, l.Line)
					found = true
				}
			}
			require.True(t, found, "a null approval must be an error; got %v", lints)
		})
	}
}

// TestValidate_ApprovalRunsForEveryRuleShape proves the approval check is
// reached for routing rules too, which return early from checkRule.
func TestValidate_ApprovalRunsForEveryRuleShape(t *testing.T) {
	t.Parallel()

	const doc = `
credstores:
  - name: default
    provider: op
rules:
  - host: api.example.com
    inject:
      type: placeholder
      template: "{{ CREDENTIAL }}"
    routes:
      - name: a
        token: tok-a
        secret_ref: op://Vault/A/field
    approval:
`
	cfg, root, err := Load(strings.NewReader(doc))
	require.NoError(t, err)
	lints := Validate(cfg, root)
	var found bool
	for _, l := range lints {
		if l.Path == "rules[0].approval" && l.Line == 14 {
			found = true
		}
	}
	require.True(t, found, "want a line-numbered approval lint; got %v", lints)
}

func TestLoad_ApprovalRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	_, _, err := Load(strings.NewReader(approvalRuleConfig("    approval: {ttl: 5m}")))
	require.ErrorContains(t, err, "field ttl not found")
}
