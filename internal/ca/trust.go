package ca

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// trustAnchorFile is the on-disk name postern uses when copying the CA into
// any trust-store directory. Keeping it stable lets uninstall find the file
// without consulting state.
const trustAnchorFile = "postern.crt"

// trustFileMode is the perm bits postern writes to a trust-store anchor.
// 0o644 is required because the per-user update-ca-certificates utility runs
// without privilege escalation but still needs to read the source file.
const trustFileMode os.FileMode = 0o644

// trustDirMode is the perm bits for an implicitly-created trust-store
// directory. 0o755 matches the layout shipped by ca-certificates on
// Debian/Ubuntu, where the directory is world-readable but only owner-writable.
const trustDirMode os.FileMode = 0o755

// ErrTrustUnsupported is returned by InstallTrust and UninstallTrust on
// platforms where postern has no built-in trust-store integration. The CLI
// surfaces this as a "manual instructions in the README" message.
var ErrTrustUnsupported = errors.New("system trust install is not supported on this platform")

// InstallTrustAt writes certPEM to <dir>/postern.crt with mode 0644, creating
// dir (and any missing parents) with mode 0755. It returns the final path on
// success. This is the testable form of InstallTrust; production callers
// invoke InstallTrust which resolves dir via the OS-specific default.
func InstallTrustAt(dir string, certPEM []byte) (string, error) {
	if err := os.MkdirAll(dir, trustDirMode); err != nil {
		return "", fmt.Errorf("create trust dir: %w", err)
	}
	path := filepath.Join(dir, trustAnchorFile)
	if err := os.WriteFile(path, certPEM, trustFileMode); err != nil {
		return path, fmt.Errorf("write trust anchor: %w", err)
	}
	if err := os.Chmod(path, trustFileMode); err != nil {
		return path, fmt.Errorf("chmod trust anchor: %w", err)
	}
	return path, nil
}

// UninstallTrustAt removes <dir>/postern.crt and returns the (former) path.
// A missing file is treated as success so the operation is idempotent.
func UninstallTrustAt(dir string) (string, error) {
	path := filepath.Join(dir, trustAnchorFile)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return path, nil
		}
		return path, fmt.Errorf("remove trust anchor: %w", err)
	}
	return path, nil
}

// DefaultTrustDir returns the OS-specific directory postern uses as the
// system trust-anchor location. It returns ErrTrustUnsupported on platforms
// that don't ship a built-in trust-store integration.
func DefaultTrustDir() (string, error) { return defaultTrustDir() }

// InstallTrust copies the CA into the OS-specific default trust-store
// directory and returns the path on success. The default location is
// determined by defaultTrustDir (set per GOOS in trust_<goos>.go).
func InstallTrust(certPEM []byte) (string, error) {
	dir, err := defaultTrustDir()
	if err != nil {
		return "", err
	}
	return InstallTrustAt(dir, certPEM)
}

// UninstallTrust removes the CA from the OS-specific default trust-store
// directory and returns the (former) path on success.
func UninstallTrust() (string, error) {
	dir, err := defaultTrustDir()
	if err != nil {
		return "", err
	}
	return UninstallTrustAt(dir)
}
