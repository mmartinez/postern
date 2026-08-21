//go:build darwin

package ca

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// securityBin is the macOS keychain/trust CLI postern shells out to. An
// absolute path so the trust decision cannot be redirected via $PATH.
const securityBin = "/usr/bin/security"

// runSecurity executes the security(1) CLI, folding its stderr diagnostics
// into the returned error. Package-level so tests can stub it out; no test
// ever invokes the real binary.
var runSecurity = func(args ...string) error {
	cmd := exec.Command(securityBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return securityCmdError(args, err, stderr.String())
	}
	return nil
}

// securityCmdError builds the wrapped error for a failed security invocation,
// quoting the full command line and appending the tool's stderr output so
// Security-framework failures are actionable.
func securityCmdError(args []string, err error, stderr string) error {
	return fmt.Errorf("%s %s: %w: %s",
		securityBin, strings.Join(args, " "), err, strings.TrimSpace(stderr))
}

// loginKeychain returns the user's login keychain. The per-user trust domain
// needs no sudo; add-trusted-cert stores the certificate there and records a
// user-domain (non-admin) trust setting for it.
func loginKeychain() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db"), nil
}

// defaultTrustDir returns the anchor PEM path postern persists under its own
// config dir: ~/.postern/trust/ca.pem. Unlike Linux's directory-based model,
// security(1) wants a file path: add-trusted-cert/remove-trusted-cert take
// the PEM directly, and the same file feeds delete-certificate's hash lookup
// on uninstall, so no state beyond the file itself is needed to undo an
// install.
func defaultTrustDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".postern", "trust", "ca.pem"), nil
}

// installTrustAt persists the anchor PEM at anchorPath (the location argument
// is the anchor file path on macOS, see DefaultTrustDir) and marks it as a
// trusted root in the user trust domain via
//
//	security add-trusted-cert -r trustRoot -k <login keychain> <pem>
//
// The user-authentication dialog this triggers is expected; per-user trust
// settings deliberately avoid sudo.
func installTrustAt(anchorPath string, certPEM []byte) (string, error) {
	if err := os.MkdirAll(filepath.Dir(anchorPath), trustDirMode); err != nil {
		return "", fmt.Errorf("create trust dir: %w", err)
	}
	if err := writeFileMode(anchorPath, certPEM, trustFileMode); err != nil {
		return anchorPath, fmt.Errorf("write trust anchor: %w", err)
	}
	keychain, err := loginKeychain()
	if err != nil {
		return anchorPath, err
	}
	if err := runSecurity([]string{
		"add-trusted-cert", "-r", "trustRoot", "-k", keychain, anchorPath,
	}...); err != nil {
		return anchorPath, fmt.Errorf("register trust anchor: %w", err)
	}
	return anchorPath, nil
}

// uninstallTrustAt revokes the CA's user trust settings
// (security remove-trusted-cert), deletes the certificate from the login
// keychain by SHA-256 hash (security delete-certificate -Z), and only then
// removes the persisted PEM. Both security calls are mandatory: skipping the
// keychain deletion would leave a "successful" uninstall with the CA still
// resolvable in the keychain, and skipping remove-trusted-cert would leave it
// explicitly trusted. A missing anchor means nothing was installed; that is a
// successful no-op so uninstall is idempotent.
func uninstallTrustAt(anchorPath string) (string, error) {
	certPEM, err := os.ReadFile(anchorPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return anchorPath, nil
		}
		return anchorPath, fmt.Errorf("read trust anchor: %w", err)
	}
	hash, err := certSHA256Hex(certPEM)
	if err != nil {
		return anchorPath, err
	}
	keychain, err := loginKeychain()
	if err != nil {
		return anchorPath, err
	}
	if err := runSecurity("remove-trusted-cert", anchorPath); err != nil {
		return anchorPath, fmt.Errorf("revoke trust settings: %w", err)
	}
	if err := runSecurity("delete-certificate", "-Z", hash, keychain); err != nil {
		return anchorPath, fmt.Errorf("delete keychain certificate: %w", err)
	}
	if err := os.Remove(anchorPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return anchorPath, fmt.Errorf("remove trust anchor: %w", err)
	}
	return anchorPath, nil
}

// certSHA256Hex returns the lowercase hex SHA-256 of the certificate's DER
// bytes, the form security(1) delete-certificate -Z matches against.
func certSHA256Hex(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("parse trust anchor: invalid PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
