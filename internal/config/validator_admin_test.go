package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// withAdminListen splices an admin_listen value into the valid fixture's
// proxy block, keeping the rest of the document (and therefore every other
// lint source) stable across the table below. The value is always quoted so
// YAML metacharacters in IPv6 literals ([::1]:port) parse as scalars.
func withAdminListen(addr string) string {
	return strings.Replace(validConfig,
		"on_no_match: passthrough",
		"on_no_match: passthrough\n  admin_listen: \""+addr+"\"",
		1)
}

// TestValidate_AdminListen covers the Proposal 3 lint contract for
// proxy.admin_listen: unset means unrestricted (zero behavior change); set,
// it must parse as host:port whose host is a loopback IP (127.0.0.0/8 or
// ::1). The admin endpoint exposes internal state, so a non-loopback bind is
// rejected with a line-numbered error before the server can start.
func TestValidate_AdminListen(t *testing.T) {
	t.Parallel()

	cases := []validateCase{
		{
			name: "unset admin_listen is fine",
			yaml: validConfig,
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints, "absent admin_listen must not produce lints")
			},
		},
		{
			name: "loopback ipv4 bind is accepted",
			yaml: withAdminListen("127.0.0.1:1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints)
			},
		},
		{
			name: "any 127.0.0.0/8 address is accepted",
			yaml: withAdminListen("127.0.0.9:1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints)
			},
		},
		{
			name: "loopback ipv6 bind is accepted",
			yaml: withAdminListen("[::1]:1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				require.Empty(t, lints)
			},
		},
		{
			name: "wildcard bind is rejected",
			yaml: withAdminListen("0.0.0.0:1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
		{
			name: "lan address is rejected",
			yaml: withAdminListen("192.168.1.10:1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
		{
			name: "hostname is rejected (loopback IP required)",
			yaml: withAdminListen("localhost:1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
		{
			name: "empty host is rejected",
			yaml: withAdminListen(":1702"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
		{
			name: "missing port is rejected",
			yaml: withAdminListen("127.0.0.1"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
		{
			name: "non-numeric port is rejected",
			yaml: withAdminListen("127.0.0.1:notaport"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
		{
			name: "out-of-range port is rejected",
			yaml: withAdminListen("127.0.0.1:99999"),
			wantLints: func(t *testing.T, lints []config.LintError) {
				requireLintContains(t, lints, "admin_listen")
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, lints, err := config.LoadAndValidate(strings.NewReader(tc.yaml))
			require.NoError(t, err, "unexpected parse-level error")
			tc.wantLints(t, lints)
		})
	}
}

// TestValidate_AdminListenErrorIsLineNumbered confirms the acceptance
// criterion that a rejected admin_listen reports the YAML line of the key,
// so `postern config validate` can point at the offending address.
func TestValidate_AdminListenErrorIsLineNumbered(t *testing.T) {
	t.Parallel()

	doc := withAdminListen("0.0.0.0:1702")
	_, lints, err := config.LoadAndValidate(strings.NewReader(doc))
	require.NoError(t, err)
	require.NotEmpty(t, lints)

	var found bool
	for _, l := range lints {
		if l.Line > 0 && strings.Contains(l.Message, "admin_listen") {
			found = true
			break
		}
	}
	require.True(t, found, "expected a lint with Line > 0 mentioning admin_listen; got %v", lints)
}
