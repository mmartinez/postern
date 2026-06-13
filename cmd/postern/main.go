// Command postern is the credential-brokering HTTPS proxy CLI.
//
// At this stage `postern --version`, `postern config init/validate`, and
// `postern token set/status/test/rm` are wired up. Subsequent slices add
// `ca`, `server`, and `rules`.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/ca"
	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/credstore/onepassword"
	"github.com/mmartinez/postern/internal/token"
	"github.com/mmartinez/postern/internal/version"
)

// opValidator implements cli.Validator by constructing a fresh credential-
// vendor client per call and pinging it via HealthCheck. A fresh client per
// validation avoids stashing the SDK client across long-lived shells where
// it'd otherwise accumulate state we'd have to manage.
type opValidator struct{}

func (opValidator) Validate(ctx context.Context, tok string) error {
	c, err := onepassword.New(ctx, tok, version.Version)
	if err != nil {
		return err
	}
	return c.HealthCheck(ctx)
}

// newStore picks the concrete token.Store implementation for the current
// host. Probe + open failures fall back to NoopStore with a warning so the
// binary stays useful for non-token subcommands; the token subcommands
// then surface ErrNoBackend with guidance.
func newStore() token.Store {
	const serviceName = "postern"
	s, err := token.Open(serviceName)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "postern: warning: %v; falling back to no-backend store\n", err)
		return token.NewNoopStore()
	}
	return s
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "postern",
		Short: "Credential-brokering HTTPS proxy for AI agents",
		Long: "postern sits between an agent and the upstream API. The agent sends\n" +
			"requests without auth headers; postern matches each request's host\n" +
			"against the config's rules, resolves the rule's secret reference,\n" +
			"and injects the credential before forwarding. Start with:\n" +
			"\n" +
			"  postern ca install         # trust the local CA\n" +
			"  postern config init        # write a starter config\n" +
			"  postern token set --stdin  # capture and store the SA token\n" +
			"  postern server             # run the proxy",
		Version: version.Version,
		// Silence cobra's default error/usage chatter on subcommand failures;
		// errors are surfaced explicitly by main.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// reg is the process-wide provider registry that onepassword's init()
	// populated on import; passing it explicitly makes the broker's provider
	// set a visible dependency of the command wiring rather than an implicit
	// effect of import order.
	reg := credstore.Default()
	cmd.AddCommand(cli.NewConfigCmd(reg))

	store := newStore()
	cmd.AddCommand(cli.NewTokenCmd(store, opValidator{}, tokenAccount()))

	cmd.AddCommand(cli.NewCACmd(defaultCADir(), defaultTrustDir()))
	cmd.AddCommand(cli.NewServerCmd(defaultCADir(), reg, store))
	cmd.AddCommand(cli.NewExecCmd(reg, store))
	cmd.AddCommand(cli.NewRulesCmd())
	cmd.AddCommand(cli.NewBootstrapCmd(defaultCADir()))

	return cmd
}

// defaultCADir returns ~/.postern, falling back to ./postern when $HOME is
// unavailable so the binary still exits with a coherent error instead of a
// panic-on-empty-path during install.
func defaultCADir() string {
	dir, err := ca.DefaultDir()
	if err != nil {
		return "postern"
	}
	return dir
}

// defaultTrustDir returns the OS-specific trust-anchor directory. An empty
// string is returned on unsupported platforms; the CLI surfaces this as an
// error when install or uninstall actually runs.
func defaultTrustDir() string {
	dir, err := ca.DefaultTrustDir()
	if err != nil {
		return ""
	}
	return dir
}

// tokenAccount returns the keychain account name. It hard-codes "default"
// to match the embedded config template; config-driven account selection
// (sharing a single Config struct across all subcommands) is not yet wired.
func tokenAccount() string { return "default" }

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if errors.Is(err, token.ErrNoBackend) {
			fmt.Fprintf(os.Stderr, "postern: error: %v\n", err)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "postern: error: %v\n", err)
		os.Exit(1)
	}
}
