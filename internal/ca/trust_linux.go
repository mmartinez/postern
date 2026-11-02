//go:build linux

package ca

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultTrustDir resolves ~/.local/share/ca-certificates, where ca install
// writes a copy of the CA. No distribution trust tool reads that directory:
// update-ca-certificates has no per-user mode, and Fedora's update-ca-trust
// and Arch's trust read system directories only. Agents trust the CA through
// SSL_CERT_FILE, which postern bootstrap sets, or through the system-store
// steps in docs/security.md, which need root, so postern does not run them.
func defaultTrustDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "ca-certificates"), nil
}

// installTrustAt on Linux writes the CA copy into dir. It adds no trust; see
// defaultTrustDir.
func installTrustAt(dir string, certPEM []byte) (string, error) {
	return writeAnchor(dir, certPEM)
}

// uninstallTrustAt on Linux removes the CA copy. There is no keychain-style
// registration to revoke, so no hashes are ever reported.
func uninstallTrustAt(dir string) ([]string, error) {
	_, err := removeAnchor(dir)
	return nil, err
}
