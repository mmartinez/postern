package cli

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/token"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// When --config is not supplied and the default config path doesn't exist,
// the broker is disabled and the server runs in passthrough mode. This is
// the behaviour the existing SIGTERM integration test relies on.
func TestBuildBrokerHook_NoConfigFile_RunsPassthrough(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "no-such-config.yaml")
	hook, err := buildBrokerHook(context.Background(), credstore.Default(), missing, false, token.NewMemoryStore(), discardLogger()) //nolint:bodyclose // hook is a closure; bodyclose can't trace ownership
	if err != nil {
		t.Fatalf("buildBrokerHook(missing, required=false): %v", err)
	}
	if hook.hook != nil {
		t.Fatalf("hook is non-nil; want nil (passthrough)")
	}
}

// When --config is supplied explicitly and the file is missing, the user
// likely typo'd a path; we must error rather than silently downgrade to
// passthrough.
func TestBuildBrokerHook_ExplicitMissingConfig_Errors(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "no-such-config.yaml")
	_, err := buildBrokerHook(context.Background(), credstore.Default(), missing, true, token.NewMemoryStore(), discardLogger()) //nolint:bodyclose // hook is a closure
	if err == nil {
		t.Fatalf("buildBrokerHook(missing, required=true): want error, got nil")
	}
}

// A valid config with zero rules disables the broker and runs passthrough
// without ever touching the token store or the credential vendor client.
func TestBuildBrokerHook_ConfigWithNoRules_RunsPassthrough(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`)

	hook, err := buildBrokerHook(context.Background(), credstore.Default(), path, true, token.NewMemoryStore(), discardLogger()) //nolint:bodyclose // hook is a closure
	if err != nil {
		t.Fatalf("buildBrokerHook(rules=[]): %v", err)
	}
	if hook.hook != nil {
		t.Fatalf("hook is non-nil; want nil (no rules to broker)")
	}
}

// A config with rules but no resolvable token is a fail-closed condition:
// the broker can't function so the server must refuse to start instead of
// silently degrading.
func TestBuildBrokerHook_RulesButNoToken_Errors(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN_DELIBERATELY_UNSET
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
`)

	_, err := buildBrokerHook(context.Background(), credstore.Default(), path, true, token.NewMemoryStore(), discardLogger()) //nolint:bodyclose // hook is a closure
	if err == nil {
		t.Fatalf("buildBrokerHook(rules + no token): want error, got nil")
	}
}

// A schema-invalid config must refuse to start even when not explicitly
// required — a broken config is never silently downgraded to passthrough.
// Here the rule is missing the required inject.template, which the
// validator flags as SeverityError.
func TestBuildBrokerHook_BrokenConfig_Errors(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
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
`)

	_, err := buildBrokerHook(context.Background(), credstore.Default(), path, false, token.NewMemoryStore(), discardLogger()) //nolint:bodyclose // hook is a closure
	if err == nil {
		t.Fatalf("buildBrokerHook(broken config): want error, got nil")
	}
}

// A valid config with no rules still surfaces proxy.listen so the server
// binds the configured port in passthrough mode — the divergence R5 fixes
// (server ignored proxy.listen while bootstrap honored it).
func TestBuildBrokerHook_NoRules_SurfacesProxyListen(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:9999
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`)

	bundle, err := buildBrokerHook(context.Background(), credstore.Default(), path, true, token.NewMemoryStore(), discardLogger()) //nolint:bodyclose // hook is a closure
	if err != nil {
		t.Fatalf("buildBrokerHook(rules=[]): %v", err)
	}
	if bundle.listen != "127.0.0.1:9999" {
		t.Fatalf("bundle.listen = %q, want %q", bundle.listen, "127.0.0.1:9999")
	}
}

// resolveListenAddr precedence: an explicit --addr flag wins; otherwise the
// config's proxy.listen; otherwise config.DefaultListenAddr. Mirrors
// bootstrap's config-first resolution so server binds the port bootstrap
// advertises.
func TestResolveListenAddr(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		flagChanged bool
		flagAddr    string
		cfgListen   string
		want        string
	}{
		{"flag overrides config", true, "127.0.0.1:7000", "127.0.0.1:9999", "127.0.0.1:7000"},
		{"flag overrides empty config", true, "127.0.0.1:7000", "", "127.0.0.1:7000"},
		{"config used when flag default", false, config.DefaultListenAddr, "127.0.0.1:9999", "127.0.0.1:9999"},
		{"default when neither set", false, config.DefaultListenAddr, "", config.DefaultListenAddr},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveListenAddr(tc.flagChanged, tc.flagAddr, tc.cfgListen); got != tc.want {
				t.Fatalf("resolveListenAddr(%v, %q, %q) = %q, want %q",
					tc.flagChanged, tc.flagAddr, tc.cfgListen, got, tc.want)
			}
		})
	}
}

// assertRulesRoutable is the boot-time fail-closed guard: a rule whose
// secret_ref scheme has no configured resolver must error at startup, not as
// a 502 on the first matching request in production.
func TestAssertRulesRoutable(t *testing.T) {
	t.Parallel()

	resolvers := map[string]broker.Resolver{"op": nil}

	if err := assertRulesRoutable([]broker.Rule{{Host: "api.example.com", SecretRef: "op://V/I/f"}}, resolvers); err != nil {
		t.Fatalf("routable rule: unexpected error %v", err)
	}

	err := assertRulesRoutable([]broker.Rule{{Host: "api.example.com", SecretRef: "bw://C/I/f"}}, resolvers)
	if err == nil {
		t.Fatalf("unroutable scheme: want error, got nil (would surface as a 502 at first request)")
	}
	if !strings.Contains(err.Error(), "bw") {
		t.Fatalf("error should name the unroutable scheme: %v", err)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
