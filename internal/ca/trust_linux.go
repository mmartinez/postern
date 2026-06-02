//go:build linux

package ca

import (
	"fmt"
	"os"
	"path/filepath"
)

// defaultTrustDir resolves the per-user CA directory consulted by
// Debian/Ubuntu's update-ca-certificates --user (and equivalent
// integrations on derivatives). The XDG layout puts it at
// ~/.local/share/ca-certificates/.
//
// Other distributions place anchors differently:
//   - Fedora / RHEL:   /etc/pki/ca-trust/source/anchors/ + update-ca-trust
//   - Arch:            /etc/ca-certificates/trust-source/anchors/ + trust extract
//
// Those paths require root and a `trust`/`update-ca-trust` follow-up, so
// postern deliberately doesn't write to them. The README documents the
// manual steps for those distros; running postern there still works as long
// as the user sets SSL_CERT_FILE=~/.postern/ca.pem in the agent's env.
func defaultTrustDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".local", "share", "ca-certificates"), nil
}
