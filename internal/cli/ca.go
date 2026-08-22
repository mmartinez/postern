package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/ca"
)

// NewCACmd builds `postern ca` with its install and uninstall subcommands.
// caDir is the directory that holds ca.pem and ca.key; trustDir is the
// system trust-anchor directory the install command publishes the CA to.
// cmd/postern/main.go wires production callers via ca.DefaultDir and
// ca.DefaultTrustDir; tests inject temp dirs.
func NewCACmd(caDir, trustDir string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "Manage the local certificate authority",
		Long: "Install or remove postern's local CA. The CA is generated on first\n" +
			"install, persisted under ~/.postern, and published to the system\n" +
			"trust store so agents can verify the proxy's minted leaf certs.",
	}
	cmd.AddCommand(newCAInstallCmd(caDir, trustDir))
	cmd.AddCommand(newCAUninstallCmd(caDir, trustDir))
	return cmd
}

func newCAInstallCmd(caDir, trustDir string) *cobra.Command {
	return &cobra.Command{
		Use:   "install",
		Short: "Generate the CA if needed and install it in the trust store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			authority, reused, err := loadOrGenerateCA(caDir)
			if err != nil {
				return err
			}
			if reused {
				_, _ = fmt.Fprintf(out, "Using existing CA at %s\n", filepath.Join(caDir, "ca.pem"))
			} else {
				_, _ = fmt.Fprintf(out, "Generated CA at %s\n", filepath.Join(caDir, "ca.pem"))
			}

			path, err := ca.InstallTrustAt(trustDir, authority.CertPEM)
			if err != nil {
				return fmt.Errorf("install trust: %w", err)
			}
			_, _ = fmt.Fprintf(out, "Installed trust anchor at %s\n", path)
			_, _ = fmt.Fprintln(out, "You can now point HTTPS_PROXY at postern.")
			return nil
		},
	}
}

func newCAUninstallCmd(caDir, trustDir string) *cobra.Command {
	var purge bool
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove the local CA from the system trust store",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			path, revoked, err := ca.UninstallTrustAt(trustDir)
			if err != nil {
				return fmt.Errorf("uninstall trust: %w", err)
			}
			_, _ = fmt.Fprintf(out, "Removed trust anchor at %s\n", path)
			for _, hash := range revoked {
				_, _ = fmt.Fprintf(out, "Revoked trusted certificate %s\n", hash)
			}

			if !purge {
				_, _ = fmt.Fprintf(out, "Left CA files in %s (run with --purge to delete)\n", caDir)
				return nil
			}
			if err := purgeCADir(caDir); err != nil {
				return fmt.Errorf("purge ca dir: %w", err)
			}
			_, _ = fmt.Fprintf(out, "deleted CA files from %s\n", caDir)
			return nil
		},
	}
	cmd.Flags().BoolVar(&purge, "purge", false, "Also delete ca.pem and ca.key from the CA directory")
	return cmd
}

// loadOrGenerateCA returns the CA at dir, generating + saving a fresh one if
// no usable CA is present. reused reports whether the returned CA was loaded
// from disk (true) or freshly minted (false).
func loadOrGenerateCA(dir string) (*ca.CA, bool, error) {
	if authority, err := ca.Load(dir); err == nil {
		return authority, true, nil
	} else if !errors.Is(err, fs.ErrNotExist) && !isMissingCAFile(err) {
		return nil, false, fmt.Errorf("load ca: %w", err)
	}

	authority, err := ca.Generate(time.Now())
	if err != nil {
		return nil, false, fmt.Errorf("generate ca: %w", err)
	}
	if err := authority.Save(dir); err != nil {
		return nil, false, fmt.Errorf("save ca: %w", err)
	}
	return authority, false, nil
}

// isMissingCAFile recognizes wrapped fs.ErrNotExist surfaces. ca.Load wraps
// the read errors with fmt.Errorf("%w"), which preserves Is matching, but
// in the unlikely future where the wrap chain changes we still want
// missing-file to mean "generate", not "fail loudly".
func isMissingCAFile(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, os.ErrNotExist)
}

// purgeCADir removes ca.pem and ca.key from dir. Missing files are accepted
// so the operation is idempotent — running `ca uninstall --purge` on a host
// that never installed must succeed.
func purgeCADir(dir string) error {
	for _, name := range []string{"ca.pem", "ca.key"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
