package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/config"
)

// NewBootstrapCmd builds `postern bootstrap`, which prints the env-var
// exports an agent shell needs so curl / SDKs route through the proxy and
// trust the local CA.
//
// The listen address comes from the config file's proxy.listen field; if
// no config exists (default path) or proxy.listen is empty,
// config.DefaultListenAddr is used as a fallback so the snippet is still
// useful before `postern config init`. caDir is the CA directory (the same
// directory ca.Save/ca.Load use); the snippet points SSL_CERT_FILE at
// ca.CertPath(caDir). caDir is taken as a constructor argument to match
// NewServerCmd and NewCACmd, since the CA directory layout is a binary-level
// convention, not a configurable field.
func NewBootstrapCmd(caDir string) *cobra.Command {
	var (
		shell      string
		configPath string
	)
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Print shell exports for HTTPS_PROXY and SSL_CERT_FILE",
		Long: "Emit a snippet you can `eval` from your shell to point HTTPS_PROXY\n" +
			"at the proxy listener and SSL_CERT_FILE at the local CA. Supports\n" +
			"bash, zsh, and fish; auto-detects from $SHELL when --shell is not\n" +
			"given and defaults to bash if detection fails. proxy.listen is read\n" +
			"from the config file when present.",
		Example: "  # bash / zsh\n" +
			"  eval \"$(postern bootstrap --shell bash)\"\n" +
			"  # fish\n" +
			"  postern bootstrap --shell fish | source",
		RunE: func(cmd *cobra.Command, _ []string) error {
			listen, err := resolveBootstrapListen(configPath)
			if err != nil {
				return err
			}
			s := shell
			if s == "" {
				s = detectShell(os.Getenv("SHELL"))
			}
			return writeBootstrap(cmd.OutOrStdout(), s, listen, ca.CertPath(caDir))
		},
	}
	cmd.Flags().StringVar(&shell, "shell", "", "Target shell: bash|zsh|fish (default $SHELL)")
	cmd.Flags().StringVar(&configPath, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	return cmd
}

// resolveBootstrapListen returns the proxy listen address. Precedence:
//  1. config file's proxy.listen when the file exists and parses cleanly
//  2. config.DefaultListenAddr otherwise
//
// A missing default-path config is fine (bootstrap should work before
// `config init`); an explicit --config that doesn't exist is an error so a
// typo doesn't silently emit the default. A schema-broken config also errors
// so we don't print a snippet for a config `postern server` would itself
// refuse to load — config.LoadForCLI enforces both gates, treating an
// explicit path as required.
func resolveBootstrapListen(configPath string) (string, error) {
	cfg, err := config.LoadForCLI(configPath, configPath != "")
	if err != nil {
		return "", err
	}
	if cfg != nil && cfg.Proxy.Listen != "" {
		return cfg.Proxy.Listen, nil
	}
	return config.DefaultListenAddr, nil
}

// detectShell maps a $SHELL path like /usr/bin/fish to the shell flavour.
// Unknown or empty input falls back to bash so the snippet is always
// usable; the user can override with --shell.
func detectShell(shellEnv string) string {
	switch filepath.Base(shellEnv) {
	case "zsh":
		return "zsh"
	case "fish":
		return "fish"
	default:
		return "bash"
	}
}

// writeBootstrap emits the export snippet for the given shell to w. The
// proxy URL is constructed from listenAddr; HTTP, not HTTPS, because the
// scheme is the protocol used to reach the proxy, not the protocol the
// proxy brokers.
//
// Values are single-quoted using each shell's literal-string syntax — not
// fmt.Fprintf %q (which is Go-syntax quoting). Double-quoted strings in
// bash, zsh, and fish still expand $, backticks, and \ at `eval` time;
// single quotes do not, so the eval-time value equals the build-time
// value byte for byte even if a path contains shell metacharacters.
func writeBootstrap(w io.Writer, shell, listenAddr, caPath string) error {
	proxyURL := "http://" + listenAddr
	switch shell {
	case "bash", "zsh":
		_, err := fmt.Fprintf(w, "export HTTPS_PROXY=%s\nexport SSL_CERT_FILE=%s\n",
			posixSingleQuote(proxyURL), posixSingleQuote(caPath))
		return err
	case "fish":
		_, err := fmt.Fprintf(w, "set -x HTTPS_PROXY %s\nset -x SSL_CERT_FILE %s\n",
			fishSingleQuote(proxyURL), fishSingleQuote(caPath))
		return err
	default:
		return fmt.Errorf("unknown --shell %q (want bash|zsh|fish)", shell)
	}
}

// posixSingleQuote wraps s in POSIX single quotes (bash, zsh, dash, etc.).
// Inside '…' the only metacharacter is '; embedded single quotes are
// closed-escaped-opened ('\”).
func posixSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishSingleQuote wraps s in fish single quotes. Fish single-quoted
// strings treat \\ and \' as escapes and everything else literally.
func fishSingleQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "'", `\'`)
	return "'" + s + "'"
}
