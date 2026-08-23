package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/mmartinez/postern/internal/config"
)

// TestSchemaRoundTrip verifies the typed Config struct survives a
// marshal → unmarshal round-trip without losing fields. Catches missing
// `yaml:` tags and accidental field renames.
func TestSchemaRoundTrip(t *testing.T) {
	t.Parallel()

	original := config.Config{
		Token: config.Token{
			Source:          config.TokenSourceAuto,
			EnvVar:          "OP_SERVICE_ACCOUNT_TOKEN",
			File:            "",
			KeychainAccount: "default",
		},
		Proxy: config.Proxy{
			Listen:    "127.0.0.1:1701",
			CacheTTL:  5 * time.Minute,
			OnNoMatch: config.OnNoMatchPassthrough,
		},
		Rules: []config.Rule{
			{
				Host:      "api.example.com",
				SecretRef: "op://Vault/Item/field",
				Inject: config.Inject{
					Type:     config.InjectTypeHeader,
					Name:     "x-api-key",
					Template: "{{ CREDENTIAL }}",
				},
			},
		},
	}

	encoded, err := yaml.Marshal(&original)
	require.NoError(t, err)

	var decoded config.Config
	require.NoError(t, yaml.Unmarshal(encoded, &decoded))

	if diff := cmp.Diff(original, decoded); diff != "" {
		t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestDefaultIsValidYAML verifies the embedded default template is
// parseable and contains the three example rules the default config ships.
func TestDefaultIsValidYAML(t *testing.T) {
	t.Parallel()

	raw := config.DefaultYAML()
	require.NotEmpty(t, raw, "DefaultYAML must not be empty")

	var c config.Config
	require.NoError(t, yaml.Unmarshal(raw, &c), "default YAML must unmarshal cleanly")

	require.Len(t, c.Rules, 3, "default must include three example rules")

	hosts := make(map[string]struct{}, len(c.Rules))
	for _, r := range c.Rules {
		hosts[r.Host] = struct{}{}
	}
	for _, want := range []string{"api.anthropic.com", "api.openai.com", "api.github.com"} {
		if _, ok := hosts[want]; !ok {
			t.Errorf("default missing rule for host %q (have %v)", want, hosts)
		}
	}
}

// TestDefaultHeaderHumanReadable spot-checks the embedded default has the
// commentary the user expects when they open the file (file is shipped to
// human operators).
func TestDefaultHeaderHumanReadable(t *testing.T) {
	t.Parallel()
	raw := string(config.DefaultYAML())
	if !strings.HasPrefix(strings.TrimSpace(raw), "#") {
		t.Errorf("default YAML should start with a comment block; first line: %q",
			strings.SplitN(raw, "\n", 2)[0])
	}
}

// scopedRuleConfig wraps a minimal valid config around the given rule body
// lines so each scoping case only varies the fragment under test.
func scopedRuleConfig(ruleBody string) string {
	return `
token:
  source: auto
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
rules:
  - host: api.example.com
    secret_ref: op://Vault/Item/field
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
` + ruleBody + "\n"
}

// TestValidatorScopingLints covers Proposal 1's validate-time criteria:
// an explicitly empty paths or methods list is an error (absent key is
// fine), every paths entry must start with "/", and every methods entry
// must be a non-empty alphabetic token — each reported with a line number.
func TestValidatorScopingLints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		ruleBody   string
		wantSubstr string // empty means expect no scoping lints at all
	}{
		{
			name:       "valid scoped rule produces no lints",
			ruleBody:   "    paths:\n      - /v1/messages\n    methods:\n      - POST\n",
			wantSubstr: "",
		},
		{
			name:       "explicitly empty paths list errors",
			ruleBody:   "    paths: []\n",
			wantSubstr: "paths",
		},
		{
			name:       "explicitly empty methods list errors",
			ruleBody:   "    methods: []\n",
			wantSubstr: "methods",
		},
		{
			name:       "paths entry without leading slash errors",
			ruleBody:   "    paths:\n      - v1/messages\n",
			wantSubstr: "paths",
		},
		{
			name:       "non-alphabetic method entry errors",
			ruleBody:   "    methods:\n      - POST2\n",
			wantSubstr: "methods",
		},
		{
			name:       "empty-string method entry errors",
			ruleBody:   "    methods:\n      - \"\"\n",
			wantSubstr: "methods",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, lints, err := config.LoadAndValidate(strings.NewReader(scopedRuleConfig(tc.ruleBody)))
			require.NoError(t, err)
			if tc.wantSubstr == "" {
				require.Empty(t, lints, "valid scoped rule must not produce lints")
				return
			}
			require.NotEmpty(t, lints, "expected a scoping lint")
			var found bool
			for _, l := range lints {
				if strings.Contains(l.Path, tc.wantSubstr) && l.Line > 0 {
					found = true
					break
				}
			}
			require.True(t, found, "expected line-numbered lint on %s; got %v", tc.wantSubstr, lints)
		})
	}
}
