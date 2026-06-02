// Package cli provides the cobra subcommand constructors. Each file exposes
// one or more New<Verb>Cmd() factories that the root command wires together
// in cmd/postern/main.go.
package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
)

// NewConfigCmd builds `postern config`, the parent for init/validate. reg is
// the credstore provider registry the validate subcommand checks references
// against.
func NewConfigCmd(reg *credstore.Registry) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage postern configuration",
		Long: "Write a starter config, or validate an existing one. The config\n" +
			"file lives at ~/.postern/config.yaml by default; --config overrides\n" +
			"the path for every subcommand below.",
	}
	cmd.AddCommand(newConfigInitCmd())
	cmd.AddCommand(newConfigValidateCmd(reg))
	return cmd
}

func newConfigInitCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Write a default config to ~/.postern/config.yaml",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target := path
			if target == "" {
				target = config.DefaultPath()
			}
			if err := config.WriteDefault(target, force); err != nil {
				if errors.Is(err, config.ErrConfigExists) {
					return err
				}
				return fmt.Errorf("init config: %w", err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", target)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing config file")
	return cmd
}

func newConfigValidateCmd(reg *credstore.Registry) *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Parse the config and report schema errors with line numbers",
		RunE: func(cmd *cobra.Command, _ []string) error {
			target := path
			if target == "" {
				target = config.DefaultPath()
			}
			_, lints, err := config.LoadFileWithProviders(target, newProviderFacts(reg))
			if err != nil {
				return err
			}

			var fatal int
			out := cmd.OutOrStdout()
			for _, l := range lints {
				_, _ = fmt.Fprintf(out, "%s: %s\n", target, l.Error())
				if l.Severity == config.SeverityError {
					fatal++
				}
			}
			if fatal > 0 {
				return fmt.Errorf("%s: %d error(s) found", target, fatal)
			}
			_, _ = fmt.Fprintf(out, "%s: ok\n", target)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "config", "", "Config file path (default: ~/.postern/config.yaml)")
	return cmd
}
