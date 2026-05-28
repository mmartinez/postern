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
			Listen:    "127.0.0.1:14321",
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
// parseable and contains the three example rules the SPEC mandates.
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
