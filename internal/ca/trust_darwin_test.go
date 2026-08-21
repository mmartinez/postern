//go:build darwin

package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// darwinFixtureCA generates a CA inside the package (the ca_test fixture
// lives in the external test package).
func darwinFixtureCA(t *testing.T) []byte {
	t.Helper()
	c, err := Generate(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	return c.CertPEM
}

// securityRecorder is an explicit securityRunner stand-in. Each invocation is
// recorded as one security(1) command line's argv (command name included,
// binary path excluded); handle, when set, answers the call instead of the
// default success-with-no-output.
type securityRecorder struct {
	calls  [][]string
	handle func(args []string) ([]byte, error)
}

func (r *securityRecorder) run(args ...string) ([]byte, error) {
	r.calls = append(r.calls, args)
	if r.handle != nil {
		return r.handle(args)
	}
	return nil, nil
}

// failingRunner returns a securityRunner whose every call fails like the real
// binary would: the error carries the full command line plus stderr text.
func failingRunner(errCode int, stderr string) securityRecorder {
	return securityRecorder{
		handle: func(args []string) ([]byte, error) {
			cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", errCode))
			runErr := cmd.Run()
			return nil, securityCmdError(args, runErr, stderr)
		},
	}
}

// securityNotFoundErr builds the error shape of a security(1) lookup that did
// not find its item: the documented exit status 44, wrapped exactly the way
// production wraps failed invocations.
func securityNotFoundErr(t *testing.T, args []string) error {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "exit 44")
	runErr := cmd.Run()
	var exitErr *exec.ExitError
	require.ErrorAs(t, runErr, &exitErr)
	require.Equal(t, 44, exitErr.ExitCode())
	return securityCmdError(args, runErr,
		"SecKeychainSearchCopyNext: The specified item could not be found in the keychain.")
}

// pemSHA256Hex returns the SHA-256 (of DER) of a PEM-encoded certificate,
// the value persisted in the state file and matched by delete-certificate -Z.
func pemSHA256Hex(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func TestDefaultTrustDir_PemUnderPosternConfigDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir, err := defaultTrustDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".postern", "trust", "ca.pem"), dir)
}

func TestInstallTrustAt_ExecutesAddTrustedCert(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &securityRecorder{}
	certPEM := darwinFixtureCA(t)

	path, err := darwinTrust{run: rec.run}.install(filepath.Join(home, ".postern", "trust", "ca.pem"), certPEM)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".postern", "trust", "ca.pem"), path)

	require.Len(t, rec.calls, 1, "install must invoke security exactly once")
	require.Equal(t,
		[]string{
			"add-trusted-cert", "-r", "trustRoot",
			"-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
			path,
		},
		rec.calls[0])

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, certPEM, got)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

// TestInstallTrustAt_PersistsSha256StateFile pins the install half of the
// P1 fix: the SHA-256 (of DER) of the registered certificate is persisted
// next to the anchor, 0600, so a later uninstall can disambiguate keychain
// generations by hash when the anchor PEM is lost.
func TestInstallTrustAt_PersistsSha256StateFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &securityRecorder{}
	certPEM := darwinFixtureCA(t)

	_, err := darwinTrust{run: rec.run}.install(filepath.Join(home, ".postern", "trust", "ca.pem"), certPEM)
	require.NoError(t, err)

	statePath := filepath.Join(home, ".postern", "trust", "ca.sha256")
	got, err := os.ReadFile(statePath)
	require.NoError(t, err, "install must persist the certificate hash for later uninstall")
	require.Equal(t, pemSHA256Hex(t, certPEM), strings.TrimSpace(string(got)))
	info, err := os.Stat(statePath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

// TestInstallTrustAt_DirectoryArgMatchesSharedContract pins the half of the
// dispatch contract the platform-independent suites rely on: a directory
// argument yields <dir>/postern.crt, byte-identical contents, mode 0644, and
// the derived path (not the raw argument) handed to security(1). The
// sibling SHA-256 state file follows the same derivation
// (postern.crt -> postern.sha256).
func TestInstallTrustAt_DirectoryArgMatchesSharedContract(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &securityRecorder{}
	certPEM := darwinFixtureCA(t)
	dir := filepath.Join(home, "trust-store")

	path, err := darwinTrust{run: rec.run}.install(dir, certPEM)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "postern.crt"), path)

	require.Len(t, rec.calls, 1)
	require.Equal(t,
		[]string{
			"add-trusted-cert", "-r", "trustRoot",
			"-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
			path,
		},
		rec.calls[0])

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, certPEM, got)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
	stateGot, err := os.ReadFile(filepath.Join(dir, "postern.sha256"))
	require.NoError(t, err)
	require.Equal(t, pemSHA256Hex(t, certPEM), strings.TrimSpace(string(stateGot)))
}

func TestUninstallTrustAt_RevokesTrustAndDeletesKeychainCert(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	rec := &securityRecorder{}

	revoked, err := darwinTrust{run: rec.run}.uninstall(anchor)
	require.NoError(t, err)

	hash := pemSHA256Hex(t, certPEM)
	require.Equal(t, []string{hash}, revoked, "the revoked certificate's hash must be reported")
	require.Len(t, rec.calls, 2, "uninstall must both revoke trust and delete the keychain cert")
	require.Equal(t, []string{"remove-trusted-cert", anchor}, rec.calls[0])
	require.Equal(t,
		[]string{"delete-certificate", "-Z", hash, keychain},
		rec.calls[1])

	_, statErr := os.Stat(anchor)
	require.True(t, os.IsNotExist(statErr), "anchor pem should be gone after uninstall")
	_, statErr = os.Stat(filepath.Join(home, ".postern", "trust", "ca.sha256"))
	require.True(t, os.IsNotExist(statErr), "state file should be gone after uninstall")
}

// TestUninstallTrustAt_AnchorMissingRecoversFromKeychain covers the security
// fix: with the persisted PEM lost but the certificate still trusted in the
// login keychain, uninstall must recover the certificate bytes by common
// name, revoke its trust setting, and delete it from the keychain. Reporting
// success without those commands would leave the CA trusted.
func TestUninstallTrustAt_AnchorMissingRecoversFromKeychain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")

	// A prior install persisted the state file; only the PEM was lost.
	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	require.NoError(t, os.Remove(anchor))

	rec := &securityRecorder{}
	var revokedPem string
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return certPEM, nil
		case "remove-trusted-cert":
			revokedPem = args[1]
			return nil, nil
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(anchor)
	require.NoError(t, err)
	require.Equal(t, []string{pemSHA256Hex(t, certPEM)}, revoked)

	require.Len(t, rec.calls, 3, "recovery must probe, revoke trust, then delete from keychain")
	require.Equal(t,
		[]string{"find-certificate", "-a", "-c", caCommonName, "-p", keychain},
		rec.calls[0])
	require.NotEqual(t, anchor, revokedPem, "revocation must use the recovered copy, not the missing anchor")
	require.True(t, strings.HasSuffix(revokedPem, ".pem"), "recovered anchor must be materialized as a PEM file")
	_, statErr := os.Stat(revokedPem)
	require.True(t, os.IsNotExist(statErr), "recovered temp copy must be cleaned up")
	require.Equal(t,
		[]string{"delete-certificate", "-Z", pemSHA256Hex(t, certPEM), keychain},
		rec.calls[2])
}

// TestUninstallTrustAt_AnchorMissingCertAbsentIsNoOp proves idempotency is
// genuine: when neither the anchor nor the keychain holds the certificate,
// uninstall succeeds without any revocation command.
func TestUninstallTrustAt_AnchorMissingCertAbsentIsNoOp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	rec := &securityRecorder{}
	rec.handle = func(args []string) ([]byte, error) {
		return nil, securityNotFoundErr(t, args)
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.NoError(t, err, "uninstall must be idempotent")
	require.Empty(t, revoked, "nothing was revoked")
	require.Len(t, rec.calls, 1, "only the keychain probe may run")
	require.Equal(t, "find-certificate", rec.calls[0][0], "no revocation without a located certificate")
}

// TestUninstallTrustAt_StateHashSelectsCorrectGeneration pins the P1 fix:
// regeneration leaves older, still-trusted Postern CAs in the login
// keychain, all sharing the common name. With the anchor PEM lost, uninstall
// must pick the generation recorded in the state file by exact SHA-256, not
// whichever common-name match the keychain returns first.
func TestUninstallTrustAt_StateHashSelectsCorrectGeneration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	stalePEM := darwinFixtureCA(t) // earlier generation, still trusted
	certPEM := darwinFixtureCA(t)  // installed generation: distinct key + serial
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	require.NoError(t, os.Remove(anchor), "simulate the lost anchor PEM")

	rec := &securityRecorder{}
	var revokedPemContent []byte
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			blob := append(append([]byte{}, stalePEM...), certPEM...)
			return blob, nil // find-certificate -a output: every generation
		case "remove-trusted-cert":
			revokedPemContent, _ = os.ReadFile(args[1])
			return nil, nil
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(anchor)
	require.NoError(t, err)

	require.Equal(t, []string{pemSHA256Hex(t, certPEM)}, revoked,
		"exactly the installed generation must be revoked")
	require.Len(t, rec.calls, 3)
	require.Equal(t,
		[]string{"find-certificate", "-a", "-c", caCommonName, "-p", keychain},
		rec.calls[0])
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	require.Equal(t, string(pem.EncodeToMemory(block)), string(revokedPemContent),
		"revocation must target the state-hash match, not the stale generation")
	require.Equal(t,
		[]string{"delete-certificate", "-Z", pemSHA256Hex(t, certPEM), keychain},
		rec.calls[2])
	require.NotContains(t, rec.calls[2], pemSHA256Hex(t, stalePEM),
		"the stale generation's hash must never be deleted via name-only recovery")
}

// TestUninstallTrustAt_NoStateRevokesAllMatches covers resolution path 3:
// with neither anchor nor state file, uninstall fails wide — revoking every
// common-name match — and reports each revoked hash.
func TestUninstallTrustAt_NoStateRevokesAllMatches(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pemA := darwinFixtureCA(t)
	pemB := darwinFixtureCA(t)
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")

	rec := &securityRecorder{}
	var revokedPems []string
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return append(append([]byte{}, pemA...), pemB...), nil
		case "remove-trusted-cert":
			content, _ := os.ReadFile(args[1])
			revokedPems = append(revokedPems, string(content))
			return nil, nil
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{pemSHA256Hex(t, pemA), pemSHA256Hex(t, pemB)}, revoked,
		"every common-name match must be reported as revoked")

	require.Len(t, rec.calls, 5, "probe plus revoke+delete per matched certificate")
	canonical := func(certPEM []byte) string {
		block, _ := pem.Decode(certPEM)
		require.NotNil(t, block)
		return string(pem.EncodeToMemory(block))
	}
	require.ElementsMatch(t, []string{canonical(pemA), canonical(pemB)}, revokedPems)
	require.ElementsMatch(t,
		[][]string{
			{"delete-certificate", "-Z", pemSHA256Hex(t, pemA), keychain},
			{"delete-certificate", "-Z", pemSHA256Hex(t, pemB), keychain},
		},
		[][]string{rec.calls[1], rec.calls[3]})
}

// TestUninstallTrustAt_KeychainProbeFailureSurfacesError ensures a real
// security(1) failure during recovery is never mistaken for "nothing to do".
func TestUninstallTrustAt_KeychainProbeFailureSurfacesError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := failingRunner(51, "SecKeychainSearchCopyNext failed\n")

	_, err := darwinTrust{run: rec.run}.uninstall(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "Postern Local CA")
	require.Contains(t, err.Error(), "SecKeychainSearchCopyNext failed",
		"security's stderr must be surfaced to the caller")
	require.Len(t, rec.calls, 1, "no revocation attempt after a failed probe")
}

func TestInstallTrustAt_SecurityFailureWrapsStderr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := failingRunner(44, "SecTrustSettingsAddTrusted failed\n")
	certPEM := darwinFixtureCA(t)

	_, err := darwinTrust{run: rec.run}.install(filepath.Join(home, ".postern", "trust", "ca.pem"), certPEM)
	require.Error(t, err)
	require.Contains(t, err.Error(), securityBin)
	require.Contains(t, err.Error(), "add-trusted-cert")
	require.Contains(t, err.Error(), "exit status 44")
	require.Contains(t, err.Error(), "SecTrustSettingsAddTrusted failed",
		"security's stderr must be surfaced to the caller")
}

func TestUninstallTrustAt_SecurityFailureWrapsStderr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	rec := failingRunner(51, "SecTrustSettingsRemoveTrusted failed\n")

	_, err = darwinTrust{run: rec.run}.uninstall(anchor)
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoke trust settings")
	require.Contains(t, err.Error(), "SecTrustSettingsRemoveTrusted failed")
}

func TestUninstallTrustAt_InvalidPemIsRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &securityRecorder{}
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	require.NoError(t, os.MkdirAll(filepath.Dir(anchor), 0o755))
	require.NoError(t, os.WriteFile(anchor, []byte("not a pem"), 0o644))

	_, err := darwinTrust{run: rec.run}.uninstall(anchor)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid PEM")
	require.Empty(t, rec.calls, "no security invocation without a parseable anchor")
}

func TestSecurityCmdError_Format(t *testing.T) {
	err := securityCmdError([]string{"remove-trusted-cert", "/x/ca.pem"},
		errors.New("exit status 1"), "boom\n")
	require.Equal(t,
		fmt.Sprintf("%s remove-trusted-cert /x/ca.pem: exit status 1: boom", securityBin),
		err.Error())
}
