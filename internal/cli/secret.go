package cli

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// SecretStore is the cli's narrow consumer interface over the OS secret store
// that keychain://<item> references resolve from. The production
// implementation is the keychain credstore provider; tests use a fake.
type SecretStore interface {
	// SetSecret stores value under the item ref names, replacing any
	// existing value.
	SetSecret(ctx context.Context, ref, value string) error
	// RemoveSecret deletes the item ref names; a missing item is not an error.
	RemoveSecret(ctx context.Context, ref string) error
}

// NewSecretCmd builds the `postern secret` parent with set and rm
// subcommands that manage keychain://<item> values in the OS secret store.
func NewSecretCmd(store SecretStore) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage credentials stored in the OS secret store",
		Long: "Store and remove the values keychain://<item> secret references\n" +
			"resolve to. Values live in the macOS Keychain or the Secret Service\n" +
			"login collection, and are never echoed to stdout.",
	}
	cmd.AddCommand(newSecretSetCmd(store))
	cmd.AddCommand(newSecretRmCmd(store))
	return cmd
}

func newSecretSetCmd(store SecretStore) *cobra.Command {
	var (
		fromStdin bool
		fromEnv   string
	)
	cmd := &cobra.Command{
		Use:   "set keychain://<item>",
		Short: "Store a value under a keychain://<item> reference",
		Long: "Reads the value from --stdin or --from-env VAR. Without either flag on\n" +
			"a terminal, prompts for the value without echoing it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			val, err := readSecret(cmd, fromStdin, fromEnv)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if err := store.SetSecret(ctx, args[0], val); err != nil {
				return fmt.Errorf("store %s: %w", args[0], err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Stored %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "Read the value from stdin")
	cmd.Flags().StringVar(&fromEnv, "from-env", "", "Read the value from the named environment variable")
	return cmd
}

func newSecretRmCmd(store SecretStore) *cobra.Command {
	return &cobra.Command{
		Use:   "rm keychain://<item>",
		Short: "Remove a stored value (idempotent)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if err := store.RemoveSecret(ctx, args[0]); err != nil {
				return fmt.Errorf("remove %s: %w", args[0], err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", args[0])
			return nil
		},
	}
}

// readSecret reads the value from the flag-selected source, or prompts
// without echo when neither flag is set and stdin is a terminal.
func readSecret(cmd *cobra.Command, fromStdin bool, fromEnv string) (string, error) {
	f, isFile := cmd.InOrStdin().(*os.File)
	if fromStdin || fromEnv != "" || !isFile || !term.IsTerminal(int(f.Fd())) {
		return readToken(cmd.InOrStdin(), fromStdin, fromEnv)
	}
	_, _ = fmt.Fprint(cmd.ErrOrStderr(), "Value: ")
	raw, err := term.ReadPassword(int(f.Fd()))
	_, _ = fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", fmt.Errorf("read value: %w", err)
	}
	if len(raw) == 0 {
		return "", errors.New("value is empty")
	}
	return string(raw), nil
}
