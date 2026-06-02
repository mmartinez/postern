package ca_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

// fixtureCA gives the trust tests a freshly-generated CA so they can be run
// independently of any other slice.
func fixtureCA(t *testing.T) *ca.CA {
	t.Helper()
	c, err := ca.Generate(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	return c
}

func TestInstallTrustAt_WritesCertWithCorrectMode(t *testing.T) {
	t.Parallel()
	c := fixtureCA(t)
	dir := t.TempDir()

	path, err := ca.InstallTrustAt(dir, c.CertPEM)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "postern.crt"), path)

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm(),
		"trust anchor must be world-readable so the system updater can ingest it")

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, c.CertPEM, got)
}

func TestInstallTrustAt_CreatesParentDir(t *testing.T) {
	t.Parallel()
	c := fixtureCA(t)
	dir := filepath.Join(t.TempDir(), "ca-certificates")

	_, err := ca.InstallTrustAt(dir, c.CertPEM)
	require.NoError(t, err)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.True(t, info.IsDir())
}

func TestInstallTrustAt_Overwrites(t *testing.T) {
	t.Parallel()
	c := fixtureCA(t)
	dir := t.TempDir()

	_, err := ca.InstallTrustAt(dir, []byte("stale"))
	require.NoError(t, err)

	path, err := ca.InstallTrustAt(dir, c.CertPEM)
	require.NoError(t, err)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, c.CertPEM, got)
}

func TestUninstallTrustAt_RemovesFile(t *testing.T) {
	t.Parallel()
	c := fixtureCA(t)
	dir := t.TempDir()
	_, err := ca.InstallTrustAt(dir, c.CertPEM)
	require.NoError(t, err)

	path, err := ca.UninstallTrustAt(dir)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(dir, "postern.crt"), path)

	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr), "trust file should be gone after uninstall")
}

func TestUninstallTrustAt_MissingFileIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, err := ca.UninstallTrustAt(dir)
	require.NoError(t, err, "uninstall must be idempotent")
}

func TestInstallTrustAt_FailsWhenParentIsFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))

	_, err := ca.InstallTrustAt(filepath.Join(blocker, "trust"), fixtureCA(t).CertPEM)
	require.Error(t, err)
}
