// Command postern is the credential-brokering HTTPS proxy CLI.
//
// At this stage only `postern --version` is wired up; subsequent slices add
// `config`, `token`, `ca`, `server`, and `rules` subcommands.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/version"
)

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
	return cmd
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "postern: error: %v\n", err)
		os.Exit(1)
	}
}
