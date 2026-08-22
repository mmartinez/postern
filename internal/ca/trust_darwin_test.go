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

// trustSettingsAbsentErrFor builds the error shape of a remove-trusted-cert
// invocation against a certificate with no trust settings: exit status 1
// with the SecTrustSettingsRemoveTrustSettings errSecItemNotFound diagnostic
// in the captured stderr, wrapped exactly the way production wraps failures.
func trustSettingsAbsentErrFor(t *testing.T, args []string) error {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", "exit 1")
	runErr := cmd.Run()
	return securityCmdError(args, runErr,
		"TrustSettings::deleteTrustSettings: SecTrustSettingsRemoveTrustSettings: The specified item could not be found in the keychain.")
}

// pemSHA256Hex returns the SHA-256 (of DER) of a PEM-encoded certificate,
// the identity reported for every revoked certificate.
func pemSHA256Hex(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// canonicalPEM re-encodes a certificate the way the keychain enumeration
// path does, so staged temp content can be compared byte-exactly.
func canonicalPEM(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	return string(pem.EncodeToMemory(block))
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

// TestInstallTrustAt_DirectoryArgMatchesSharedContract pins the half of the
// dispatch contract the platform-independent suites rely on: a directory
// argument yields <dir>/postern.crt, byte-identical contents, mode 0644, and
// the derived path (not the raw argument) handed to security(1).
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
}

// TestInstallTrustAt_FailedRegistrationRemovesAnchor pins the install failure
// story: registration is the only fallible step after the anchor write, and
// when it fails the freshly persisted anchor file is removed so a reported
// install failure leaves neither trust settings nor a stale anchor behind.
func TestInstallTrustAt_FailedRegistrationRemovesAnchor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rec := &securityRecorder{handle: func(args []string) ([]byte, error) {
		if args[0] != "add-trusted-cert" {
			return nil, nil
		}
		cmd := exec.Command("/bin/sh", "-c", "exit 51")
		runErr := cmd.Run()
		return nil, securityCmdError(args, runErr, "SecTrustSettingsAddTrusted failed\n")
	}}
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	_, err := darwinTrust{run: rec.run}.install(anchor, certPEM)
	require.Error(t, err)
	require.Contains(t, err.Error(), "add-trusted-cert")
	require.Contains(t, err.Error(), "exit status 51")
	require.Contains(t, err.Error(), "SecTrustSettingsAddTrusted failed",
		"security's stderr must be surfaced to the caller")

	_, statErr := os.Stat(anchor)
	require.True(t, os.IsNotExist(statErr), "failed install must not leave the anchor behind")
}

// TestInstallTrustAt_FailedReinstallRestoresPriorAnchor pins the reinstall
// half of the failure story: writeAnchor overwrites the previous anchor
// before registration runs, so a failed reinstall must put the previous
// bytes back instead of deleting the file. Otherwise disk and keychain
// diverge — the previously trusted CA keeps its trust settings while its
// persisted anchor is gone.
func TestInstallTrustAt_FailedReinstallRestoresPriorAnchor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	priorPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, priorPEM)
	require.NoError(t, err)
	newPEM := darwinFixtureCA(t)
	rec := &securityRecorder{handle: func(args []string) ([]byte, error) {
		if args[0] != "add-trusted-cert" {
			return nil, nil
		}
		cmd := exec.Command("/bin/sh", "-c", "exit 51")
		runErr := cmd.Run()
		return nil, securityCmdError(args, runErr, "SecTrustSettingsAddTrusted failed\n")
	}}

	_, err = darwinTrust{run: rec.run}.install(anchor, newPEM)
	require.Error(t, err)

	got, readErr := os.ReadFile(anchor)
	require.NoError(t, readErr, "the pre-existing anchor must survive a failed reinstall")
	require.Equal(t, priorPEM, got,
		"failed reinstall must restore the previous anchor bytes, not delete them")
}

// TestUninstallTrustAt_RevokesAnchorDirectlyAndLeavesKeychainEntry covers the
// common uninstall: the anchor PEM is present and the same certificate sits
// in the login keychain. The certificate must be revoked exactly once,
// through the anchor's real path (no temp staging for a deduplicated
// candidate), and the keychain entry must be left in place — no
// delete-certificate anywhere.
func TestUninstallTrustAt_RevokesAnchorDirectlyAndLeavesKeychainEntry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	rec := &securityRecorder{}
	rec.handle = func(args []string) ([]byte, error) {
		if args[0] == "find-certificate" {
			return certPEM, nil
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(anchor)
	require.NoError(t, err)

	hash := pemSHA256Hex(t, certPEM)
	require.Equal(t, []string{hash}, revoked, "the revoked certificate's hash must be reported")
	require.Len(t, rec.calls, 2, "keychain probe plus exactly one revocation")
	require.Equal(t, []string{"remove-trusted-cert", anchor}, rec.calls[1],
		"the anchor's real path must be passed to remove-trusted-cert")
	for _, call := range rec.calls {
		require.NotEqual(t, "delete-certificate", call[0],
			"revocation-only uninstall never deletes keychain entries")
	}

	_, statErr := os.Stat(anchor)
	require.True(t, os.IsNotExist(statErr), "anchor pem should be gone after uninstall")
}

// TestUninstallTrustAt_WideRevocationCoversBothGenerations pins the wide
// revocation contract: when the login keychain holds two independently
// generated Postern CAs, uninstall revokes the trust settings of BOTH —
// one remove-trusted-cert per unique certificate, in any order — and issues
// zero delete-certificate calls anywhere. Wide revocation is what makes a
// multi-generation keychain safe by construction: name-based enumeration
// cannot leave a still-trusted Postern generation behind.
func TestUninstallTrustAt_WideRevocationCoversBothGenerations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pemA := darwinFixtureCA(t) // earlier generation, still trusted
	pemB := darwinFixtureCA(t) // installed generation

	rec := &securityRecorder{}
	revokedPEM := map[string]bool{} // canonical staged PEM -> seen
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return append(append([]byte{}, pemA...), pemB...), nil
		case "remove-trusted-cert":
			content, _ := os.ReadFile(args[1])
			if block, _ := pem.Decode(content); block != nil {
				revokedPEM[canonicalPEM(t, content)] = true
			}
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.NoError(t, err)

	require.ElementsMatch(t,
		[]string{pemSHA256Hex(t, pemA), pemSHA256Hex(t, pemB)}, revoked,
		"every same-name certificate must be reported as revoked")
	require.Len(t, rec.calls, 3, "keychain probe plus one remove-trusted-cert per unique certificate")
	removes := 0
	for _, call := range rec.calls {
		require.NotEqual(t, "delete-certificate", call[0],
			"revocation-only uninstall never deletes keychain entries")
		if call[0] == "remove-trusted-cert" {
			removes++
		}
	}
	require.Equal(t, 2, removes, "exactly one remove-trusted-cert per unique certificate")
	require.True(t, revokedPEM[canonicalPEM(t, pemA)], "generation A's trust settings must be revoked")
	require.True(t, revokedPEM[canonicalPEM(t, pemB)], "generation B's trust settings must be revoked")
}

// TestUninstallTrustAt_AnchorMissingRecoversFromKeychain covers the lost
// anchor: with the persisted PEM gone but the certificate still trusted in
// the login keychain, uninstall must recover the certificate bytes by common
// name, stage them to a temp file, and revoke their trust settings. Reporting
// success without that command would leave the CA trusted.
func TestUninstallTrustAt_AnchorMissingRecoversFromKeychain(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)

	rec := &securityRecorder{}
	var stagedPEM string
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return certPEM, nil
		case "remove-trusted-cert":
			stagedPEM = string(mustRead(t, args[1]))
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.NoError(t, err)

	require.Equal(t, []string{pemSHA256Hex(t, certPEM)}, revoked)
	require.Len(t, rec.calls, 2, "keychain probe plus exactly one revocation")
	require.Equal(t, "remove-trusted-cert", rec.calls[1][0])
	require.Equal(t, canonicalPEM(t, certPEM), stagedPEM,
		"revocation must target the certificate recovered from the keychain")
	for _, call := range rec.calls {
		require.NotEqual(t, "delete-certificate", call[0],
			"revocation-only uninstall never deletes keychain entries")
	}
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

// TestUninstallTrustAt_RetryIsIdempotent pins the single-operation contract:
// running uninstall twice yields identical successful outcomes. On the retry
// the certificate still shows up in the keychain (the entry is intentionally
// left in place) but its trust settings are already gone, which
// remove-trusted-cert reports as errSecItemNotFound — classified as
// satisfied, not fatal. There is no second phase to strand, so the retry
// cannot wedge.
func TestUninstallTrustAt_RetryIsIdempotent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	hash := pemSHA256Hex(t, certPEM)

	first := &securityRecorder{}
	first.handle = func(args []string) ([]byte, error) {
		if args[0] == "find-certificate" {
			return certPEM, nil
		}
		return nil, nil
	}
	revoked, err := darwinTrust{run: first.run}.uninstall(anchor)
	require.NoError(t, err)
	require.Equal(t, []string{hash}, revoked)

	second := &securityRecorder{}
	second.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return certPEM, nil // keychain entry intentionally survives
		case "remove-trusted-cert":
			return nil, trustSettingsAbsentErrFor(t, args)
		}
		return nil, nil
	}
	revoked, err = darwinTrust{run: second.run}.uninstall(anchor)
	require.NoError(t, err, "retry must succeed: absent trust settings are the goal state")
	require.Equal(t, []string{hash}, revoked, "the certificate still counts as satisfied")

	for _, rec := range []*securityRecorder{first, second} {
		for _, call := range rec.calls {
			require.NotEqual(t, "delete-certificate", call[0],
				"no residual trust intent may involve keychain deletion")
		}
	}
}

// TestUninstallTrustAt_RevocationFailureAbortsAndReportsCompletedSoFar pins
// the error contract: a genuine remove-trusted-cert failure (not an
// absence diagnostic) aborts the remaining work, surfaces security's stderr,
// and still reports every hash revoked before the failure.
func TestUninstallTrustAt_RevocationFailureAbortsAndReportsCompletedSoFar(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pemA := darwinFixtureCA(t)
	pemB := darwinFixtureCA(t)

	rec := &securityRecorder{}
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return append(append([]byte{}, pemA...), pemB...), nil
		case "remove-trusted-cert":
			content, _ := os.ReadFile(args[1])
			if canonicalPEM(t, content) == canonicalPEM(t, pemB) {
				cmd := exec.Command("/bin/sh", "-c", "exit 51")
				runErr := cmd.Run()
				return nil, securityCmdError(args, runErr, "SecTrustSettingsRemoveTrusted failed\n")
			}
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoke trust settings")
	require.Contains(t, err.Error(), "SecTrustSettingsRemoveTrusted failed",
		"security's stderr must be surfaced to the caller")
	require.Equal(t, []string{pemSHA256Hex(t, pemA)}, revoked,
		"hashes revoked before the failure must be reported")
}

// TestUninstallTrustAt_KeychainProbeFailureSurfacesError ensures a real
// security(1) failure during enumeration is never mistaken for "nothing to
// do": the probe runs before any mutation, so the abort leaves the host
// exactly as it was.
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

// TestUninstallTrustAt_ProbeFailureLeavesAnchorIntact pins the abort
// contract for a present anchor: a failing keychain probe aborts before any
// mutation, so the persisted anchor survives for a later retry.
func TestUninstallTrustAt_ProbeFailureLeavesAnchorIntact(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	rec := failingRunner(51, "SecKeychainSearchCopyNext failed\n")

	_, err = darwinTrust{run: rec.run}.uninstall(anchor)
	require.Error(t, err)
	_, statErr := os.Stat(anchor)
	require.NoError(t, statErr, "a failed uninstall must not consume the anchor")
}

// TestUninstallTrustAt_RemoveReportsAbsentCountsAsSatisfied pins the
// classification seam: a remove-trusted-cert that reports no trust settings
// for the certificate (a retry, or an entry installed by another tool) is
// the state revocation aims for and must not fail the uninstall.
func TestUninstallTrustAt_RemoveReportsAbsentCountsAsSatisfied(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	rec := &securityRecorder{}
	rec.handle = func(args []string) ([]byte, error) {
		switch args[0] {
		case "find-certificate":
			return nil, securityNotFoundErr(t, args)
		case "remove-trusted-cert":
			return nil, trustSettingsAbsentErrFor(t, args)
		}
		return nil, nil
	}

	revoked, err := darwinTrust{run: rec.run}.uninstall(anchor)
	require.NoError(t, err, "absent trust settings are the goal state, not a failure")
	require.Equal(t, []string{pemSHA256Hex(t, certPEM)}, revoked)

	_, statErr := os.Stat(anchor)
	require.True(t, os.IsNotExist(statErr), "a satisfied uninstall still removes the anchor")
}

// TestUninstallTrustAt_SecurityFailureWrapsStderr ensures a genuine
// revocation failure (not an absence diagnostic) is wrapped with the command
// line and security's stderr.
func TestUninstallTrustAt_SecurityFailureWrapsStderr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")

	seedRec := &securityRecorder{}
	_, err := darwinTrust{run: seedRec.run}.install(anchor, certPEM)
	require.NoError(t, err)
	rec := &securityRecorder{handle: func(args []string) ([]byte, error) {
		if args[0] != "remove-trusted-cert" {
			return nil, securityNotFoundErr(t, args)
		}
		cmd := exec.Command("/bin/sh", "-c", "exit 51")
		runErr := cmd.Run()
		return nil, securityCmdError(args, runErr, "SecTrustSettingsRemoveTrusted failed\n")
	}}

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

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}
