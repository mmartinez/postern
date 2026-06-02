package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/config"
)

const (
	testCADir  = "/home/user/.postern"
	testCACert = "/home/user/.postern/ca.pem"
)

// runBootstrap drives the bootstrap subcommand with a fresh, isolated
// HOME so the default-config-path lookup can't pick up the host's real
// ~/.postern/config.yaml. The t.Setenv call also serializes the test
// against the rest of the suite — callers must NOT call t.Parallel(),
// since the Go runtime forbids t.Setenv after t.Parallel.
func runBootstrap(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	cmd := cli.NewBootstrapCmd(testCADir)
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

func writeBootstrapConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	return p
}

const validConfigListenOverride = `
token:
  source: env
  env_var: OP_SERVICE_ACCOUNT_TOKEN
proxy:
  listen: 127.0.0.1:24321
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`

func TestBootstrap_BashEmitsPosixExports(t *testing.T) {
	out, _, err := runBootstrap(t, "--shell", "bash")
	require.NoError(t, err)
	require.Contains(t, out, `export HTTPS_PROXY='http://`+config.DefaultListenAddr+`'`)
	require.Contains(t, out, `export SSL_CERT_FILE='`+testCACert+`'`)
}

func TestBootstrap_ZshSameAsBash(t *testing.T) {
	bashOut, _, err := runBootstrap(t, "--shell", "bash")
	require.NoError(t, err)
	zshOut, _, err := runBootstrap(t, "--shell", "zsh")
	require.NoError(t, err)
	require.Equal(t, bashOut, zshOut, "bash and zsh snippets must be identical")
}

func TestBootstrap_FishEmitsSetX(t *testing.T) {
	out, _, err := runBootstrap(t, "--shell", "fish")
	require.NoError(t, err)
	require.Contains(t, out, `set -x HTTPS_PROXY 'http://`+config.DefaultListenAddr+`'`)
	require.Contains(t, out, `set -x SSL_CERT_FILE '`+testCACert+`'`)
	require.NotContains(t, out, "export ", "fish output must not use POSIX export syntax")
}

func TestBootstrap_RejectsUnknownShell(t *testing.T) {
	_, _, err := runBootstrap(t, "--shell", "csh")
	require.Error(t, err)
	require.Contains(t, err.Error(), "bash|zsh|fish")
}

func TestBootstrap_DetectsShellFromEnv(t *testing.T) {
	cases := []struct {
		name      string
		shellEnv  string
		wantToken string
	}{
		{"fish from /usr/bin/fish", "/usr/bin/fish", "set -x HTTPS_PROXY"},
		{"zsh from /bin/zsh", "/bin/zsh", "export HTTPS_PROXY"},
		{"unset SHELL defaults to bash", "", "export HTTPS_PROXY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SHELL", tc.shellEnv)
			out, _, err := runBootstrap(t)
			require.NoError(t, err)
			require.Contains(t, out, tc.wantToken)
		})
	}
}

func TestBootstrap_SnippetEvalParity(t *testing.T) {
	for _, sh := range []string{"bash", "zsh"} {
		out, _, err := runBootstrap(t, "--shell", sh)
		require.NoError(t, err)
		lines := nonEmptyNonCommentLines(out)
		require.Len(t, lines, 2, "%s: want exactly 2 export lines, got %q", sh, out)
		for _, l := range lines {
			require.True(t, strings.HasPrefix(l, "export "), "%s: line %q missing export prefix", sh, l)
		}
	}
	out, _, err := runBootstrap(t, "--shell", "fish")
	require.NoError(t, err)
	lines := nonEmptyNonCommentLines(out)
	require.Len(t, lines, 2)
	for _, l := range lines {
		require.True(t, strings.HasPrefix(l, "set -x "), "fish: line %q missing `set -x` prefix", l)
	}
}

func TestBootstrap_UsesProxyListenFromConfig(t *testing.T) {
	p := writeBootstrapConfig(t, validConfigListenOverride)
	out, _, err := runBootstrap(t, "--shell", "bash", "--config", p)
	require.NoError(t, err)
	require.Contains(t, out, `export HTTPS_PROXY='http://127.0.0.1:24321'`)
	require.NotContains(t, out, config.DefaultListenAddr,
		"config-supplied proxy.listen must take precedence over DefaultListenAddr")
}

func TestBootstrap_FallsBackToDefaultWhenNoConfig(t *testing.T) {
	// HOME is overridden inside runBootstrap; no default config file exists
	// at <home>/.postern/config.yaml, so bootstrap must use the default
	// listen address and exit cleanly.
	out, _, err := runBootstrap(t, "--shell", "bash")
	require.NoError(t, err)
	require.Contains(t, out, "http://"+config.DefaultListenAddr)
}

func TestBootstrap_ErrorsOnExplicitMissingConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.yaml")
	_, _, err := runBootstrap(t, "--shell", "bash", "--config", missing)
	require.Error(t, err, "explicit --config that doesn't exist must fail loudly")
}

// A YAML-parseable config with a fatal schema error (e.g. invalid
// inject.type) must fail bootstrap loudly so the user fixes the file
// instead of pasting a snippet for a config that `postern server` would
// refuse to load. Mirrors config.LoadForCLI's lint-severity gate.
// Quoting must be shell-safe, not Go-syntax: the snippet is run through
// `eval` and bash/zsh/fish all expand $, backticks, and \ inside double
// quotes. Paths containing those characters are legal on Unix (HOME on a
// shared host can be /home/foo$bar). The snippet must single-quote so
// the eval-time string equals the build-time string byte for byte.
func TestBootstrap_QuotesPathsShellSafe(t *testing.T) {
	cmd := cli.NewBootstrapCmd("/home/foo$bar")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--shell", "bash"})
	require.NoError(t, cmd.Execute())
	require.Contains(t, out.String(), "/home/foo$bar/ca.pem")
	require.NotContains(t, out.String(), `"/home/foo$bar/ca.pem"`,
		"double-quoted snippet would let bash expand $bar at eval time")
}

func TestBootstrap_ErrorsOnSchemaInvalidConfig(t *testing.T) {
	schemaBroken := `
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
      type: smuggle
      name: x-api-key
      template: "{{ CREDENTIAL }}"
`
	p := writeBootstrapConfig(t, schemaBroken)
	_, _, err := runBootstrap(t, "--shell", "bash", "--config", p)
	require.Error(t, err, "schema-broken config must fail bootstrap")
	require.Contains(t, err.Error(), "schema")
}

func nonEmptyNonCommentLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}
