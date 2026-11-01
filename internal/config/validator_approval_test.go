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
		wantLine int    // 0 means the approval line, 12
	}{
		{name: "empty mapping on linux", approval: "    approval: {}", goos: "linux"},
		{name: "absent block", approval: "", goos: "darwin"},
		{name: "positive ttl", approval: "    approval:\n      ttl: 10m", goos: "linux"},
		{name: "zero ttl", approval: "    approval:\n      ttl: 0s", goos: "linux"},
		{
			name:     "negative ttl",
			approval: "    approval:\n      ttl: -1m",
			goos:     "linux",
			wantMsg:  "ttl must be zero or positive",
			wantLine: 13,
		},
		{
			name:     "approval methods a case-variant subset of the rule's",
			approval: "    methods: [GET, POST]\n    approval:\n      methods: [post]",
			goos:     "linux",
		},
		{name: "approval methods without rule methods", approval: "    approval:\n      methods: [POST]", goos: "linux"},
		{
			name:     "approval method outside the rule's",
			approval: "    methods: [GET, POST]\n    approval:\n      methods:\n        - POST\n        - DELETE",
			goos:     "linux",
			wantMsg:  `"DELETE" is not in the rule's methods`,
			wantLine: 16,
		},
		{
			name:     "approval method not a token",
			approval: "    approval:\n      methods: [P0ST]",
			goos:     "linux",
			wantMsg:  `"P0ST" must be a non-empty alphabetic HTTP method token (e.g. POST)`,
			wantLine: 13,
		},
		{
			name:     "empty approval methods",
			approval: "    approval:\n      methods: []",
			goos:     "linux",
			wantMsg:  "methods is empty; declare at least one entry or omit the key entirely (an omitted methods requires approval for every method)",
			wantLine: 13,
		},
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
			wantLine := 12
			if tc.wantLine != 0 {
				wantLine = tc.wantLine
			}
			require.Equal(t, wantLine, got.Line, "lint must point at the offending line")
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

// TestCheckApproval_FieldLineThroughAliasOrMerge proves an approval field
// error points at the line the value was read from when the block reaches
// the rule through an alias or a merge key.
func TestCheckApproval_FieldLineThroughAliasOrMerge(t *testing.T) {
	t.Parallel()

	const anchored = `
credstores:
  - name: default
    provider: op
    settings: &gate
      ttl: -1m
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`
	cases := []struct {
		name     string
		approval string
	}{
		{name: "alias", approval: "    approval: *gate"},
		{name: "merge key", approval: "    approval:\n      <<: *gate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, root, err := Load(strings.NewReader(anchored + tc.approval + "\n"))
			require.NoError(t, err)
			v := newValidator(root)
			v.goos = "linux"
			v.checkApproval("rules[0]", cfg.Rules[0])
			require.Len(t, v.out, 1)
			require.Equal(t, "rules[0].approval.ttl", v.out[0].Path)
			require.Equal(t, 6, v.out[0].Line)
		})
	}
}

// TestCheckApproval_MethodsThroughAliasOrMerge proves approval.methods is
// checked, with the line of the offending value, when it reaches the rule
// through an alias or a merge key.
func TestCheckApproval_MethodsThroughAliasOrMerge(t *testing.T) {
	t.Parallel()

	const anchored = `
credstores:
  - name: default
    provider: op
rules:
  - host: a.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
    methods: [GET, POST]
    paths: &empty []
    approval: &block
      methods: &post [POST]
  - host: b.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
    methods: [GET]
`
	const notInRule = `"POST" is not in the rule's methods`
	cases := []struct {
		name     string
		approval string
		wantPath string
		wantMsg  string
		wantLine int
	}{
		{name: "aliased block", approval: "    approval: *block", wantPath: "rules[1].approval.methods[0]", wantMsg: notInRule, wantLine: 15},
		{name: "merged block", approval: "    approval:\n      <<: *block", wantPath: "rules[1].approval.methods[0]", wantMsg: notInRule, wantLine: 15},
		{name: "aliased list", approval: "    approval:\n      methods: *post", wantPath: "rules[1].approval.methods[0]", wantMsg: notInRule, wantLine: 15},
		{
			name:     "aliased empty list",
			approval: "    approval:\n      methods: *empty",
			wantPath: "rules[1].approval.methods",
			wantMsg:  "methods is empty",
			wantLine: 24,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, root, err := Load(strings.NewReader(anchored + tc.approval + "\n"))
			require.NoError(t, err)
			v := newValidator(root)
			v.goos = "linux"
			v.checkApproval("rules[1]", cfg.Rules[1])
			require.Len(t, v.out, 1, "got %v", v.out)
			require.Equal(t, tc.wantPath, v.out[0].Path)
			require.Contains(t, v.out[0].Message, tc.wantMsg)
			require.Equal(t, tc.wantLine, v.out[0].Line)
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

	_, _, err := Load(strings.NewReader(approvalRuleConfig("    approval: {timeout: 5m}")))
	require.ErrorContains(t, err, "field timeout not found")
}
