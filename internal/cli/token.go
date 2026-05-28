package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/token"
)

// Validator is the cli's narrow consumer interface over the credential-vendor
// HealthCheck. It exists so the token subcommands can be exercised with a
// hand-written fake without dragging the SDK into unit tests; the real
// production implementation lives in cmd/postern and wraps onepassword.New +
// HealthCheck.
type Validator interface {
	// Validate proves the given service-account token can authenticate
	// against the credential vendor. It returns nil on success and a
	// wrapped error otherwise. The token must not appear in the returned
	// error.
	Validate(ctx context.Context, token string) error
}

// NewTokenCmd builds the `postern token` parent and wires the four
// subcommands set/status/test/rm against the provided store and validator.
// account is the keychain account name used by every subcommand — typically
// resolved from cfg.Token.KeychainAccount before construction so the cobra
// tree itself stays config-agnostic.
func NewTokenCmd(store token.Store, validator Validator, account string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage the credential-vendor service-account token",
	}
	cmd.AddCommand(newTokenSetCmd(store, validator, account))
	cmd.AddCommand(newTokenStatusCmd(store, account))
	cmd.AddCommand(newTokenTestCmd(store, validator, account))
	cmd.AddCommand(newTokenRmCmd(store, account))
	return cmd
}

func newTokenSetCmd(store token.Store, validator Validator, account string) *cobra.Command {
	var (
		fromStdin bool
		fromEnv   string
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Capture a service-account token, validate it, and store it",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := readToken(cmd.InOrStdin(), fromStdin, fromEnv)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if err := validator.Validate(ctx, tok); err != nil {
				return fmt.Errorf("validate token: %w", err)
			}
			if err := store.Set(ctx, account, tok); err != nil {
				return fmt.Errorf("store token: %w", err)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Validated against credential vendor\n")
			_, _ = fmt.Fprintf(out, "Stored in %s backend (account: %s)\n", store.Backend(), account)
			_, _ = fmt.Fprintf(out, "Fingerprint: %s\n", token.Fingerprint(tok))
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromStdin, "stdin", false, "Read token from stdin (single line, trailing newline stripped)")
	cmd.Flags().StringVar(&fromEnv, "from-env", "", "Read token from the named environment variable")
	return cmd
}

func newTokenStatusCmd(store token.Store, account string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether a token is stored and its fingerprint",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			tok, err := store.Get(ctx, account)
			if err != nil {
				if errors.Is(err, token.ErrNotFound) {
					return fmt.Errorf("no token stored for account %q (run `postern token set`)", account)
				}
				return fmt.Errorf("read token: %w", err)
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "backend:     %s\n", store.Backend())
			_, _ = fmt.Fprintf(out, "account:     %s\n", account)
			_, _ = fmt.Fprintf(out, "fingerprint: %s\n", token.Fingerprint(tok))
			return nil
		},
	}
}

func newTokenTestCmd(store token.Store, validator Validator, account string) *cobra.Command {
	return &cobra.Command{
		Use:   "test",
		Short: "Re-validate the stored token against the credential vendor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			tok, err := store.Get(ctx, account)
			if err != nil {
				if errors.Is(err, token.ErrNotFound) {
					return fmt.Errorf("no token stored for account %q (run `postern token set`)", account)
				}
				return fmt.Errorf("read token: %w", err)
			}
			if err := validator.Validate(ctx, tok); err != nil {
				return fmt.Errorf("token invalid: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Token valid")
			return nil
		},
	}
}

func newTokenRmCmd(store token.Store, account string) *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Remove the stored token (idempotent)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if err := store.Delete(ctx, account); err != nil {
				return fmt.Errorf("delete token: %w", err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Removed")
			return nil
		},
	}
}

// readToken pulls the token text from whichever source was configured. It
// trims a single trailing newline so paste-from-clipboard and echo-piping
// both work without surprises.
func readToken(stdin io.Reader, fromStdin bool, fromEnv string) (string, error) {
	if fromStdin && fromEnv != "" {
		return "", errors.New("--stdin and --from-env are mutually exclusive")
	}
	if !fromStdin && fromEnv == "" {
		return "", errors.New("specify --stdin or --from-env VAR")
	}
	if fromEnv != "" {
		v, ok := os.LookupEnv(fromEnv)
		if !ok || v == "" {
			return "", fmt.Errorf("environment variable %q is not set", fromEnv)
		}
		return strings.TrimRight(v, "\n"), nil
	}
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	tok := strings.TrimRight(string(raw), "\n")
	if tok == "" {
		return "", errors.New("stdin is empty")
	}
	return tok, nil
}
