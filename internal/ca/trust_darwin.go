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

// securityRunner executes one security(1) command line and returns its
// stdout. It is injected into the trust backend as a struct field so tests
// record invocations instead of touching the real login keychain; there is
// no assignable package-level state to stub.
type securityRunner func(args ...string) ([]byte, error)

// osSecurity executes the real security(1) CLI, folding its stderr
// diagnostics into the returned error.
func osSecurity(args ...string) ([]byte, error) {
	cmd := exec.Command(securityBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, securityCmdError(args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// darwinTrust is the macOS trust backend. run is the security(1) executor,
// held per-backend rather than in a global so parallel tests never share or
// reorder command behavior.
type darwinTrust struct {
	run securityRunner
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
// config dir: ~/.postern/trust/ca.pem. The .pem suffix makes resolveAnchorPath
// treat it as an explicit anchor file; a directory argument would select
// <dir>/postern.crt instead (see InstallTrustAt for the contract).
func defaultTrustDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".postern", "trust", "ca.pem"), nil
}

func installTrustAt(location string, certPEM []byte) (string, error) {
	return darwinTrust{run: osSecurity}.install(location, certPEM)
}

func uninstallTrustAt(location string) (string, error) {
	return darwinTrust{run: osSecurity}.uninstall(location)
}

// install persists the anchor PEM at the resolved anchor path and marks it as
// a trusted root in the user trust domain via
//
//	security add-trusted-cert -r trustRoot -k <login keychain> <pem>
//
// The user-authentication dialog this triggers is expected; per-user trust
// settings deliberately avoid sudo.
func (b darwinTrust) install(location string, certPEM []byte) (string, error) {
	anchorPath, err := writeAnchor(location, certPEM)
	if err != nil {
		return anchorPath, err
	}
	keychain, err := loginKeychain()
	if err != nil {
		return anchorPath, err
	}
	if _, err := b.run("add-trusted-cert", "-r", "trustRoot", "-k", keychain, anchorPath); err != nil {
		return anchorPath, fmt.Errorf("register trust anchor: %w", err)
	}
	return anchorPath, nil
}

// uninstall revokes the CA's user trust settings (security remove-trusted-cert),
// deletes the certificate from the login keychain by SHA-256 hash
// (security delete-certificate -Z), and removes the persisted PEM. Both
// security calls are mandatory: skipping the keychain deletion would leave a
// "successful" uninstall with the CA still resolvable in the keychain, and
// skipping remove-trusted-cert would leave it explicitly trusted.
//
// Revocation must not depend on the anchor file: when the PEM is missing but
// the certificate is still in the keychain, it is recovered by common name
// (security find-certificate), staged into a temp file, and revoked from
// there. Only when neither anchor nor keychain holds the CA is this a success
// no-op.
func (b darwinTrust) uninstall(location string) (string, error) {
	anchorPath := resolveAnchorPath(location)
	certPEM, readErr := os.ReadFile(anchorPath)
	recovered := false
	switch {
	case readErr == nil:
	case errors.Is(readErr, fs.ErrNotExist):
		pemBytes, err := b.findKeychainCert()
		if err != nil {
			return anchorPath, err
		}
		if pemBytes == nil {
			return anchorPath, nil
		}
		certPEM = pemBytes
		recovered = true
	default:
		return anchorPath, fmt.Errorf("read trust anchor: %w", readErr)
	}

	hash, err := certSHA256Hex(certPEM)
	if err != nil {
		return anchorPath, err
	}
	keychain, err := loginKeychain()
	if err != nil {
		return anchorPath, err
	}

	revokePath := anchorPath
	if recovered {
		tmp, err := stageRecoveredPem(certPEM)
		if err != nil {
			return anchorPath, err
		}
		defer os.Remove(tmp)
		revokePath = tmp
	}

	if _, err := b.run("remove-trusted-cert", revokePath); err != nil {
		return anchorPath, fmt.Errorf("revoke trust settings: %w", err)
	}
	if _, err := b.run("delete-certificate", "-Z", hash, keychain); err != nil {
		return anchorPath, fmt.Errorf("delete keychain certificate: %w", err)
	}
	if err := os.Remove(anchorPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return anchorPath, fmt.Errorf("remove trust anchor: %w", err)
	}
	return anchorPath, nil
}

// findKeychainCert recovers the postern CA certificate bytes from the login
// keychain after the persisted anchor went missing. A nil result with a nil
// error means the keychain holds no postern certificate either.
func (b darwinTrust) findKeychainCert() ([]byte, error) {
	keychain, err := loginKeychain()
	if err != nil {
		return nil, err
	}
	out, err := b.run("find-certificate", "-c", caCommonName, "-p", keychain)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
			return nil, nil // security(1)'s documented item-not-found status
		}
		return nil, fmt.Errorf("locate %q in login keychain: %w", caCommonName, err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	return out, nil
}

// stageRecoveredPem writes recovered certificate PEM to a temp file so
// remove-trusted-cert has a real path to operate on.
func stageRecoveredPem(certPEM []byte) (string, error) {
	f, err := os.CreateTemp("", "postern-anchor-*.pem")
	if err != nil {
		return "", fmt.Errorf("stage recovered trust anchor: %w", err)
	}
	if _, err := f.Write(certPEM); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("stage recovered trust anchor: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("stage recovered trust anchor: %w", err)
	}
	return f.Name(), nil
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
