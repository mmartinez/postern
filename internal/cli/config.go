// Package cli provides the cobra subcommand constructors. Each file exposes
// one or more New<Verb>Cmd() factories that the root command wires together
// in cmd/postern/main.go.
package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/config"
)

// defaultConfigPath returns the standard config path (~/.postern/config.yaml)
// or falls back to ./postern.yaml when $HOME is unavailable.
func defaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "postern.yaml"
	}
	return filepath.Join(home, ".postern", "config.yaml")
}

// NewConfigCmd builds `postern config`, the parent for init/validate.
func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage postern configuration",
	}
	cmd.AddCommand(newConfigInitCmd())
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
				target = defaultConfigPath()
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
	cmd.Flags().StringVar(&path, "config", "", "Path to the config file (default: ~/.postern/config.yaml)")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing config file")
	return cmd
}
