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

	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/onepassword"
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
		Use:     "postern",
		Short:   "Credential-brokering HTTPS proxy for AI agents",
		Version: version.Version,
		// Silence cobra's default error/usage chatter on subcommand failures;
		// errors are surfaced explicitly by main.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(cli.NewConfigCmd())

	store := newStore()
	cmd.AddCommand(cli.NewTokenCmd(store, opValidator{}, tokenAccount()))

	return cmd
}

// tokenAccount returns the keychain account name. M1 uses a fixed default
// since the config-driven wiring happens once T4's runtime lands and shares
// a single Config struct across all subcommands; until then `postern token`
// hard-codes "default" to match the embedded config template.
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
