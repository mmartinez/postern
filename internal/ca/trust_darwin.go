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

// trustSettingsAbsentErr reports whether a failed remove-trusted-cert
// invocation means only that the certificate holds no trust settings in
// the target domain rather than a genuine tooling failure. The
// trusted_cert_remove tool collapses every SecTrustSettingsRemoveTrustSettings
// OSStatus into exit status 1 (its own return value is unconditionally 1 on
// error), so absence is identified by the framework's cssmPerror diagnostic
// in the captured stderr: TrustSettings::deleteTrustSettings throws
// errSecItemNotFound when the certificate has no entry in the domain's
// trust dictionary.
func trustSettingsAbsentErr(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "SecTrustSettingsRemoveTrustSettings") &&
		strings.Contains(msg, "could not be found")
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

// install persists the anchor PEM at the resolved anchor path and then marks
// it as a trusted root in the user trust domain via
//
//	security add-trusted-cert -r trustRoot -k <login keychain> <pem>
//
// This is the whole install: no sibling state file, because uninstall does
// not need a persisted identity record (it revokes every same-name
// certificate it can find; see uninstall).
//
// The ordering is the failure story: the only fallible step after the anchor
// write is the registration itself. When registration fails the freshly
// persisted anchor file is removed best-effort, so a reported install
// failure leaves neither trust settings nor a stale anchor behind.
//
// The user-authentication dialog add-trusted-cert triggers is expected;
// per-user trust settings deliberately avoid sudo.
func (b darwinTrust) install(location string, certPEM []byte) (string, error) {
	keychain, err := loginKeychain()
	if err != nil {
		return "", fmt.Errorf("resolve login keychain: %w", err)
	}
	path, err := writeAnchor(location, certPEM)
	if err != nil {
		return path, err
	}
	if _, err := b.run("add-trusted-cert", "-r", "trustRoot", "-k", keychain, path); err != nil {
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return path, errors.Join(
				fmt.Errorf("register trust anchor: %w", err),
				fmt.Errorf("remove trust anchor: %w", rmErr))
		}
		return path, fmt.Errorf("register trust anchor: %w", err)
	}
	return path, nil
}

// trustTarget is one certificate uninstall will revoke: pem holds the
// canonical certificate bytes, and path is non-empty when that certificate
// is also the persisted anchor file itself, letting security(1) read the
// real path instead of a staged temp copy.
type trustTarget struct {
	pem  []byte
	path string
}

// uninstall revokes the user-domain trust settings of every Postern CA
// certificate the host holds:
//
//	security remove-trusted-cert <pem>
//
// once per unique certificate, where the candidates are the persisted anchor
// PEM (if present) plus every certificate the login keychain reports under
// the Postern common name (find-certificate -a -c ... -p), deduplicated by
// SHA-256 of DER. It returns the hash of every certificate whose trust
// settings were removed.
//
// The keychain entries are deliberately left in place — only the trust
// settings are revoked, never delete-certificate. A self-signed root without
// explicit trust settings is untrusted by macOS by default, so deleting the
// entry adds nothing except a second fallible command; mkcert's
// truststore_darwin.go makes exactly this choice (uninstall runs only
// remove-trusted-cert and leaves the CA in the keychain). With deletion gone,
// uninstall is a single idempotent operation: re-running it repeats
// remove-trusted-cert, which succeeds both when the settings are already
// absent (errSecItemNotFound is classified as satisfied, not fatal) and when
// they are still present, so no partial state can wedge a retry. Revoking
// wide is also what keeps a multi-generation keychain safe: the common name
// is shared by every generation of the CA, so name-based enumeration plus
// per-certificate revocation cannot leave a still-trusted Postern CA behind,
// whatever happened to the anchor file.
//
// Genuine errors — a missing security binary, a locked or failing keychain,
// malformed input such as an unparseable anchor PEM — abort with wrapped
// stderr and the hashes revoked so far. Only when neither the anchor nor the
// keychain yields a candidate is this a success no-op.
func (b darwinTrust) uninstall(location string) ([]string, error) {
	anchorPath := resolveAnchorPath(location)

	var targets []trustTarget
	switch certPEM, err := os.ReadFile(anchorPath); {
	case err == nil:
		// Malformed input aborts before any mutation: postern must not
		// shell out on bytes it cannot identify.
		if _, derr := certSHA256Hex(certPEM); derr != nil {
			return nil, derr
		}
		targets = append(targets, trustTarget{pem: certPEM, path: anchorPath})
	case errors.Is(err, fs.ErrNotExist):
		// No anchor: keychain enumeration alone drives revocation.
	default:
		return nil, fmt.Errorf("read trust anchor: %w", err)
	}
	keychainCerts, err := b.findKeychainCerts()
	if err != nil {
		return nil, err
	}
	for _, certPEM := range keychainCerts {
		targets = append(targets, trustTarget{pem: certPEM})
	}
	targets = dedupeTargets(targets)
	if len(targets) == 0 {
		return nil, nil // genuine no-op: neither anchor nor keychain holds the CA
	}

	revoked := make([]string, 0, len(targets))
	for _, target := range targets {
		hash, err := b.revoke(target)
		if err != nil {
			return revoked, err // report what completed so far
		}
		revoked = append(revoked, hash)
	}

	// The persisted anchor copy is derived state; drop it once nothing it
	// names is trusted anymore. A missing file is fine (nothing was
	// persisted, or a previous run already removed it).
	if err := os.Remove(anchorPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return revoked, fmt.Errorf("remove trust anchor: %w", err)
	}
	return revoked, nil
}

// revoke removes one certificate's user-domain trust settings. Anchor-derived
// targets hand security(1) the anchor's real path; keychain-derived
// certificates are staged to a temp PEM first because remove-trusted-cert
// needs a file. An errSecItemNotFound-style diagnostic means the certificate
// already has no trust settings — exactly the state revocation aims for — so
// it counts as satisfied; any other failure is fatal.
func (b darwinTrust) revoke(target trustTarget) (string, error) {
	hash, err := certSHA256Hex(target.pem)
	if err != nil {
		return "", err
	}
	pemPath := target.path
	if pemPath == "" {
		tmp, err := stageRecoveredPem(target.pem)
		if err != nil {
			return "", err
		}
		pemPath = tmp
		defer os.Remove(tmp)
	}
	if _, err := b.run("remove-trusted-cert", pemPath); err != nil && !trustSettingsAbsentErr(err) {
		return "", fmt.Errorf("revoke trust settings: %w", err)
	}
	return hash, nil
}

// dedupeTargets collapses targets carrying the same certificate (matched by
// SHA-256 of DER, so PEM formatting differences cannot split one certificate
// into two targets) and keeps the variant bound to the persisted anchor file
// when there is one, so the common case revokes through a real path instead
// of a staged temp copy.
func dedupeTargets(targets []trustTarget) []trustTarget {
	seen := make(map[string]int, len(targets))
	unique := make([]trustTarget, 0, len(targets))
	for _, target := range targets {
		block, _ := pem.Decode(target.pem)
		if block == nil {
			continue // unreachable: callers validate before building targets
		}
		sum := sha256.Sum256(block.Bytes)
		key := string(sum[:])
		if i, ok := seen[key]; ok {
			if unique[i].path == "" {
				unique[i].path = target.path
			}
			continue
		}
		seen[key] = len(unique)
		unique = append(unique, target)
	}
	return unique
}

// findKeychainCerts enumerates every certificate in the login keychain whose
// common name matches the postern CA name, returned as canonical PEM, one
// entry per certificate. A nil result with a nil error means the keychain
// holds no postern certificate. Enumerating all matches
// (find-certificate -a) instead of taking the first is what makes a
// multi-generation keychain safe: every generation gets revoked rather than
// whichever certificate the search happens to return first.
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
// bytes, the identity reported to the caller for each revoked certificate.
func certSHA256Hex(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("parse trust anchor: invalid PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}
