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

func uninstallTrustAt(location string) ([]string, error) {
	return darwinTrust{run: osSecurity}.uninstall(location)
}

// install persists the anchor PEM at the resolved anchor path, marks it as a
// trusted root in the user trust domain via
//
//	security add-trusted-cert -r trustRoot -k <login keychain> <pem>
//
// and records the certificate's SHA-256 (of DER) in a sibling state file.
// The state file is the identity record uninstall falls back to when the
// anchor PEM is lost: the common name is shared by every generation of the
// CA, so the hash is what disambiguates the right certificate in a keychain
// holding several still-trusted Postern CAs.
//
// The user-authentication dialog add-trusted-cert triggers is expected;
// per-user trust settings deliberately avoid sudo.
//
// Install is atomic on failure: the previous anchor PEM and state file are
// snapshotted before anything is mutated, and any failure after that point
// restores the exact pre-install pairing and (when add-trusted-cert already
// completed) revokes the registration. A failed install therefore never
// leaves a trusted certificate, and a failed reinstall never leaves the new
// anchor paired with the previous hash — a mismatch that would later send
// anchor-present uninstall at an already-rolled-back certificate while the
// previously installed generation stayed trusted.
func (b darwinTrust) install(location string, certPEM []byte) (string, error) {
	anchorPath := resolveAnchorPath(location)
	snap, err := snapshotTrustFiles(anchorPath)
	if err != nil {
		return anchorPath, err
	}
	hash, err := certSHA256Hex(certPEM)
	if err != nil {
		return anchorPath, fmt.Errorf("digest trust anchor: %w", err)
	}
	keychain, err := loginKeychain()
	if err != nil {
		return anchorPath, fmt.Errorf("resolve login keychain: %w", err)
	}
	anchorPath, err = writeAnchor(location, certPEM)
	if err != nil {
		return anchorPath, err
	}

	fail := func(cause error, registered bool) (string, error) {
		if rbErr := b.rollbackInstall(anchorPath, hash, keychain, snap, registered); rbErr != nil {
			return anchorPath, errors.Join(cause, rbErr)
		}
		return anchorPath, cause
	}

	if _, err := b.run("add-trusted-cert", "-r", "trustRoot", "-k", keychain, anchorPath); err != nil {
		return fail(fmt.Errorf("register trust anchor: %w", err), false)
	}
	if err := writeStateFile(anchorStatePath(anchorPath), hash); err != nil {
		return fail(fmt.Errorf("write trust state: %w", err), true)
	}
	return anchorPath, nil
}

// trustFilesSnapshot holds the pre-install bytes of the anchor PEM and its
// sibling state file. ok=false means the file was absent before the install,
// so restore removes it rather than writing empty content.
type trustFilesSnapshot struct {
	anchor   []byte
	anchorOK bool
	state    []byte
	stateOK  bool
}

func keychainOf(keychain string) string { return keychain }

// snapshotTrustFiles captures the current anchor and state bytes. An
// unreadable anchor aborts the install before any mutation; an unreadable
// state file is treated as absent, since restore would remove it anyway.
func snapshotTrustFiles(anchorPath string) (trustFilesSnapshot, error) {
	var snap trustFilesSnapshot
	data, err := os.ReadFile(anchorPath)
	switch {
	case err == nil:
		snap.anchor, snap.anchorOK = data, true
	case !errors.Is(err, fs.ErrNotExist):
		return snap, fmt.Errorf("snapshot trust anchor: %w", err)
	}
	data, err = os.ReadFile(anchorStatePath(anchorPath))
	if err == nil {
		snap.state, snap.stateOK = data, true
	}
	return snap, nil
}

// rollbackInstall undoes every mutation a failed install made: the completed
// keychain registration (when registered is true) and the on-disk anchor and
// state files. Best effort: every rollback failure is returned so it is
// surfaced alongside the original error instead of silently swallowed.
func (b darwinTrust) rollbackInstall(anchorPath, hash, keychain string, snap trustFilesSnapshot, registered bool) error {
	var errs []error
	if registered {
		if _, err := b.run("remove-trusted-cert", anchorPath); err != nil {
			errs = append(errs, fmt.Errorf("rollback revoke trust settings: %w", err))
		}
		if _, err := b.run("delete-certificate", "-Z", hash, keychain); err != nil {
			errs = append(errs, fmt.Errorf("rollback delete keychain certificate: %w", err))
		}
	}
	if err := restoreTrustFiles(snap, anchorPath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// restoreTrustFiles puts the anchor and state files back to their pre-install
// contents, removing files that did not exist before the install.
func restoreTrustFiles(snap trustFilesSnapshot, anchorPath string) error {
	var errs []error
	if snap.anchorOK {
		if err := writeFileMode(anchorPath, snap.anchor, trustFileMode); err != nil {
			errs = append(errs, fmt.Errorf("restore trust anchor: %w", err))
		}
	} else if err := os.Remove(anchorPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("restore trust anchor: %w", err))
	}
	statePath := anchorStatePath(anchorPath)
	if snap.stateOK {
		if err := writeFileMode(statePath, snap.state, 0o600); err != nil {
			errs = append(errs, fmt.Errorf("restore trust state: %w", err))
		}
	} else if err := os.Remove(statePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, fmt.Errorf("restore trust state: %w", err))
	}
	return errors.Join(errs...)
}

// uninstall revokes the CA's user trust settings (security
// remove-trusted-cert), deletes the certificate from the login keychain by
// SHA-256 hash (security delete-certificate -Z), and removes the persisted
// PEM plus its sibling SHA-256 state file. It returns the hashes of every
// certificate actually revoked; the list is empty only when nothing was
// revoked. Both security calls are mandatory per certificate: skipping the
// keychain deletion would leave a "successful" uninstall with the CA still
// resolvable in the keychain, and skipping remove-trusted-cert would leave
// it explicitly trusted.
//
// Revocation must not depend on the anchor file, and the common name is not
// an identity: every generation of the CA shares it, and regeneration can
// leave older, still-trusted Postern CAs in the keychain. The target is
// therefore resolved in order:
//
//  1. anchor PEM present — revoke it directly.
//  2. anchor missing, state file present — enumerate ALL login-keychain
//     certificates with the postern common name (find-certificate -a) and
//     revoke the one whose SHA-256 matches the persisted state hash.
//  3. neither — revoke ALL common-name matches (fail wide, never silently
//     narrow), surfacing every revoked hash to the caller.
//
// Only when neither anchor nor keychain holds the CA is this a success
// no-op.
func (b darwinTrust) uninstall(location string) ([]string, error) {
	anchorPath := resolveAnchorPath(location)
	certPEM, readErr := os.ReadFile(anchorPath)
	switch {
	case readErr == nil:
		hash, err := certSHA256Hex(certPEM)
		if err != nil {
			return nil, err
		}
		keychain, err := loginKeychain()
		if err != nil {
			return nil, err
		}
		if _, err := b.run("remove-trusted-cert", anchorPath); err != nil {
			return nil, fmt.Errorf("revoke trust settings: %w", err)
		}
		if _, err := b.run("delete-certificate", "-Z", hash, keychain); err != nil {
			return nil, fmt.Errorf("delete keychain certificate: %w", err)
		}
		if err := removeAnchorFiles(anchorPath); err != nil {
			return nil, err
		}
		return []string{hash}, nil
	case errors.Is(readErr, fs.ErrNotExist):
		return b.uninstallRecovered(anchorPath)
	default:
		return nil, fmt.Errorf("read trust anchor: %w", readErr)
	}
}

// uninstallRecovered resolves the revocation target from the login keychain
// after the anchor PEM went missing: exact SHA-256 match against the
// persisted state hash when available, otherwise every common-name match.
func (b darwinTrust) uninstallRecovered(anchorPath string) ([]string, error) {
	stateHash, hasState, err := readStateHash(anchorPath)
	if err != nil {
		return nil, err
	}
	candidates, err := b.findKeychainCerts()
	if err != nil {
		return nil, err
	}
	candidates = dedupePEMCerts(candidates)

	var targets [][]byte
	if hasState {
		for _, cert := range candidates {
			hash, err := certSHA256Hex(cert)
			if err != nil {
				return nil, fmt.Errorf("identify %q in login keychain: %w", caCommonName, err)
			}
			if hash == stateHash {
				targets = append(targets, cert)
			}
		}
	}
	if len(targets) == 0 {
		// No state file, or the state hash matches none of the enumerated
		// certificates: fail wide and revoke every common-name match rather
		// than silently narrowing to (at best) nothing.
		targets = candidates
	}
	if len(targets) == 0 {
		return nil, nil // genuine no-op: nothing matches
	}

	revoked := make([]string, 0, len(targets))
	for _, cert := range targets {
		hash, err := b.revokeRecoveredCert(cert)
		if err != nil {
			return revoked, err
		}
		revoked = append(revoked, hash)
	}
	if err := os.Remove(anchorStatePath(anchorPath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return revoked, fmt.Errorf("remove trust state: %w", err)
	}
	return revoked, nil
}

// revokeRecoveredCert revokes trust for one certificate recovered from the
// keychain: the PEM is staged to a temp file for remove-trusted-cert and the
// certificate is deleted from the login keychain by SHA-256 hash. Returns
// the revoked certificate's hash.
func (b darwinTrust) revokeRecoveredCert(certPEM []byte) (string, error) {
	hash, err := certSHA256Hex(certPEM)
	if err != nil {
		return "", err
	}
	keychain, err := loginKeychain()
	if err != nil {
		return "", err
	}
	tmp, err := stageRecoveredPem(certPEM)
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp)
	if _, err := b.run("remove-trusted-cert", tmp); err != nil {
		return "", fmt.Errorf("revoke trust settings: %w", err)
	}
	if _, err := b.run("delete-certificate", "-Z", hash, keychain); err != nil {
		return "", fmt.Errorf("delete keychain certificate: %w", err)
	}
	return hash, nil
}

// findKeychainCerts enumerates every certificate in the login keychain whose
// common name matches the postern CA name, returned as canonical PEM, one
// entry per certificate. A nil result with a nil error means the keychain
// holds no postern certificate. Enumerating all matches
// (find-certificate -a) instead of taking the first is what makes a
// multi-generation keychain safe: the caller selects by SHA-256 rather than
// by whichever certificate the search happens to return first.
func (b darwinTrust) findKeychainCerts() ([][]byte, error) {
	keychain, err := loginKeychain()
	if err != nil {
		return nil, err
	}
	out, err := b.run("find-certificate", "-a", "-c", caCommonName, "-p", keychain)
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
	return splitPEMCerts(out), nil
}

// splitPEMCerts decodes every PEM block in data and re-encodes it in
// canonical form, turning concatenated find-certificate -p output into one
// entry per certificate.
func splitPEMCerts(data []byte) [][]byte {
	var certs [][]byte
	rest := data
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			return certs
		}
		certs = append(certs, pem.EncodeToMemory(block))
		rest = remainder
	}
}

// dedupePEMCerts collapses byte-identical certificates so a certificate
// listed more than once by find-certificate -a is only revoked once.
func dedupePEMCerts(certs [][]byte) [][]byte {
	seen := make(map[string]bool, len(certs))
	unique := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		if seen[string(cert)] {
			continue
		}
		seen[string(cert)] = true
		unique = append(unique, cert)
	}
	return unique
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

// trustStateSuffix marks the sibling file that persists the SHA-256 (of DER)
// of the certificate an install actually registered:
// ~/.postern/trust/ca.pem keeps it at ~/.postern/trust/ca.sha256. The anchor
// PEM alone is not a reliable identity record (it can be lost) and the
// common name is shared by every generation of the CA, so uninstall needs
// the hash to pick the right keychain certificate.
const trustStateSuffix = ".sha256"

// anchorStatePath maps an anchor PEM path to its sibling SHA-256 state file.
func anchorStatePath(anchorPath string) string {
	return strings.TrimSuffix(anchorPath, filepath.Ext(anchorPath)) + trustStateSuffix
}

// writeStateFile atomically persists the hex SHA-256 next to the anchor.
// The file is 0600 and any missing parent directory is created 0700: the
// hash is not secret, but there is no reason for it to be group/world
// accessible. The rename lands the full content in one step, so a crash
// mid-write can never leave a truncated hash behind.
func writeStateFile(path, hexHash string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create trust state dir: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".")
	if err != nil {
		return fmt.Errorf("write trust state: %w", err)
	}
	tmp := f.Name()
	if _, err := f.WriteString(hexHash); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write trust state: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write trust state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("write trust state: %w", err)
	}
	return nil
}

// readStateHash loads the persisted SHA-256 for the anchor at anchorPath.
// hasState is false when the file is missing or does not hold a well-formed
// hash; a corrupt state file degrades to the fail-wide recovery path instead
// of blocking uninstall.
func readStateHash(anchorPath string) (string, bool, error) {
	data, err := os.ReadFile(anchorStatePath(anchorPath))
	if errors.Is(err, fs.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read trust state: %w", err)
	}
	hash := strings.TrimSpace(string(data))
	if len(hash) != sha256.Size*2 {
		return "", false, nil
	}
	if _, err := hex.DecodeString(hash); err != nil {
		return "", false, nil
	}
	return hash, true, nil
}

// removeAnchorFiles removes the anchor PEM and its sibling state file. A
// missing file is a no-op.
func removeAnchorFiles(anchorPath string) error {
	for _, path := range []string{anchorPath, anchorStatePath(anchorPath)} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove trust anchor: %w", err)
		}
	}
	return nil
}
