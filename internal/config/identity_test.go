package config_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

func TestIdentityConfig(t *testing.T) {
	t.Parallel()
	_, verifier, err := identity.Generate()
	require.NoError(t, err)
	base := "proxy:\n  listen: 127.0.0.1:1701\n  cache_ttl: 1h\n"
	for _, tc := range []struct {
		name, mode, agents string
		valid              bool
	}{
		{"legacy", "", "", true},
		{"deny all", "  client_auth: required\n", "", true},
		{"enrolled", "  client_auth: required\n", fmt.Sprintf("agents:\n  - name: Agent_1\n    key_sha256: %s\n", verifier), true},
		{"implicit off", "", fmt.Sprintf("agents:\n  - name: a\n    key_sha256: %s\n", verifier), false},
		{"invalid mode", "  client_auth: unknown\n", "", false},
		{"invalid name", "  client_auth: required\n", fmt.Sprintf("agents:\n  - name: bad.name\n    key_sha256: %s\n", verifier), false},
		{"invalid verifier", "  client_auth: required\n", "agents:\n  - name: a\n    key_sha256: invalid\n", false},
		{"duplicate", "  client_auth: required\n", fmt.Sprintf("agents:\n  - name: a\n    key_sha256: %s\n  - name: b\n    key_sha256: %s\n", verifier, verifier), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, lints, err := config.LoadAndValidate(strings.NewReader(base + tc.mode + tc.agents))
			require.NoError(t, err)
			fatal := false
			for _, lint := range lints {
				require.False(t, strings.Contains(lint.Error(), verifier), "lint exposed verifier")
				if lint.Severity == config.SeverityError {
					fatal = true
					require.Positive(t, lint.Line)
				}
			}
			require.Equal(t, !tc.valid, fatal)
		})
	}
}

func TestRequiredNetworkAuthRequiresProtectedTransport(t *testing.T) {
	t.Parallel()
	base := "proxy:\n  listen: 0.0.0.0:1701\n  cache_ttl: 1h\n  client_auth: required\n"
	for _, tc := range []struct {
		extra string
		valid bool
	}{
		{"", false},
		{"  externally_protected: true\n", true},
		{"  tls:\n    names: [proxy.example.test]\n", true},
		{"  tls:\n    names: []\n", false},
	} {
		_, lints, err := config.LoadAndValidate(strings.NewReader(base + tc.extra))
		require.NoError(t, err)
		fatal := false
		for _, l := range lints {
			if l.Severity == config.SeverityError {
				fatal = true
			}
		}
		require.Equal(t, !tc.valid, fatal)
	}
}

func TestIdentityParseErrorsDoNotExposeEnrollmentValues(t *testing.T) {
	t.Parallel()
	_, hash, err := identity.Generate()
	require.NoError(t, err)
	for _, agents := range []string{
		fmt.Sprintf("agents: %s\n", hash),
		fmt.Sprintf("agents:\n  - name: a\n    key_sha256: [%s]\n", hash),
		fmt.Sprintf("agents:\n  - name: a\n    key_sha256: %s\n    unknown: %s\n", hash, hash),
	} {
		_, _, err := config.LoadAndValidate(strings.NewReader(agents))
		require.Error(t, err)
		require.False(t, strings.Contains(err.Error(), hash[:4]), "parse diagnostic exposed verifier material")
		require.Contains(t, err.Error(), "line")
	}
}
