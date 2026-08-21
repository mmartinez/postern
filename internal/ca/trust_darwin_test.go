//go:build darwin

package ca

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
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

// stubSecurity replaces runSecurity with a recorder. It returns the recorded
// invocations; each element is one security(1) command line's argv (command
// name included, binary path excluded).
func stubSecurity(t *testing.T) *[][]string {
	t.Helper()
	calls := &[][]string{}
	orig := runSecurity
	runSecurity = func(args ...string) error {
		*calls = append(*calls, args)
		return nil
	}
	t.Cleanup(func() { runSecurity = orig })
	return calls
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
	calls := stubSecurity(t)
	certPEM := darwinFixtureCA(t)

	path, err := InstallTrustAt(filepath.Join(home, ".postern", "trust", "ca.pem"), certPEM)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".postern", "trust", "ca.pem"), path)

	require.Len(t, *calls, 1, "install must invoke security exactly once")
	require.Equal(t,
		[]string{
			"add-trusted-cert", "-r", "trustRoot",
			"-k", filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
			path,
		},
		(*calls)[0])

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, certPEM, got)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestUninstallTrustAt_RevokesTrustAndDeletesKeychainCert(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	certPEM := darwinFixtureCA(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")

	// Stub before install: the real security(1) would fail on CI (no login
	// keychain). A first recorder covers setup; a fresh one captures only
	// the uninstall invocations asserted below.
	stubSecurity(t)

	_, err := InstallTrustAt(anchor, certPEM)
	require.NoError(t, err)
	calls := stubSecurity(t)

	path, err := UninstallTrustAt(anchor)
	require.NoError(t, err)
	require.Equal(t, anchor, path)

	require.Len(t, *calls, 2, "uninstall must both revoke trust and delete the keychain cert")
	require.Equal(t, []string{"remove-trusted-cert", anchor}, (*calls)[0])

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	sum := sha256.Sum256(block.Bytes)
	require.Equal(t,
		[]string{"delete-certificate", "-Z", hex.EncodeToString(sum[:]), keychain},
		(*calls)[1])

	_, statErr := os.Stat(anchor)
	require.True(t, os.IsNotExist(statErr), "anchor pem should be gone after uninstall")
}

func TestUninstallTrustAt_MissingAnchorIsNoOp(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	calls := stubSecurity(t)

	_, err := UninstallTrustAt(filepath.Join(home, ".postern", "trust", "ca.pem"))
	require.NoError(t, err, "uninstall must be idempotent")
	require.Empty(t, *calls, "no security invocation without an installed anchor")
}

func TestInstallTrustAt_SecurityFailureWrapsStderr(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	orig := runSecurity
	runSecurity = func(args ...string) error {
		return securityCmdError(args, errors.New("exit status 44"),
			"SecTrustSettingsAddTrusted failed\n")
	}
	t.Cleanup(func() { runSecurity = orig })
	certPEM := darwinFixtureCA(t)

	_, err := InstallTrustAt(filepath.Join(home, ".postern", "trust", "ca.pem"), certPEM)
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

	// Stub before install: the real security(1) would fail on CI (no login
	// keychain); the recorder no-op is swapped for the failing stub below.
	stubSecurity(t)

	_, err := InstallTrustAt(anchor, certPEM)
	require.NoError(t, err)
	orig := runSecurity
	runSecurity = func(args ...string) error {
		return securityCmdError(args, errors.New("exit status 51"),
			"SecTrustSettingsRemoveTrusted failed\n")
	}
	t.Cleanup(func() { runSecurity = orig })

	_, err = UninstallTrustAt(anchor)
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoke trust settings")
	require.Contains(t, err.Error(), "SecTrustSettingsRemoveTrusted failed")
}

func TestUninstallTrustAt_InvalidPemIsRejected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	calls := stubSecurity(t)
	anchor := filepath.Join(home, ".postern", "trust", "ca.pem")
	require.NoError(t, os.MkdirAll(filepath.Dir(anchor), 0o755))
	require.NoError(t, os.WriteFile(anchor, []byte("not a pem"), 0o644))

	_, err := UninstallTrustAt(anchor)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid PEM")
	require.Empty(t, *calls, "no security invocation without a parseable anchor")
}

func TestSecurityCmdError_Format(t *testing.T) {
	err := securityCmdError([]string{"remove-trusted-cert", "/x/ca.pem"},
		errors.New("exit status 1"), "boom\n")
	require.Equal(t,
		fmt.Sprintf("%s remove-trusted-cert /x/ca.pem: exit status 1: boom", securityBin),
		err.Error())
}
