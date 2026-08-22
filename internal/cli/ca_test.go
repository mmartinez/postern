//go:build linux

// The ca install/uninstall flows shell out to the OS trust store via
// internal/ca. On macOS that means the real security(1) binary (no stub seam
// across packages), so these tests stay linux-only; see
// internal/ca/trust_darwin_test.go for darwin trust-store coverage.
package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/cli"
)

func runCACmd(t *testing.T, args []string, caDir, trustDir string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := cli.NewCACmd(caDir, trustDir)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCAInstall_GeneratesAndCopiesToTrustStore(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	stdout, _, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)

	// CA files exist with the documented modes.
	pemInfo, err := os.Stat(filepath.Join(caDir, "ca.pem"))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), pemInfo.Mode().Perm())

	dirInfo, err := os.Stat(caDir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	// Trust anchor was published.
	_, err = os.Stat(filepath.Join(trustDir, "postern.crt"))
	require.NoError(t, err)

	require.Contains(t, stdout, "Generated CA at")
	require.Contains(t, stdout, "Installed trust anchor at")
}

func TestCAInstall_ReusesExistingCA(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	_, _, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)
	firstPEM, err := os.ReadFile(filepath.Join(caDir, "ca.pem"))
	require.NoError(t, err)

	// Second install must NOT regenerate — otherwise the prior trust anchor
	// would no longer match any minted leaf, breaking running clients.
	stdout, _, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)
	secondPEM, err := os.ReadFile(filepath.Join(caDir, "ca.pem"))
	require.NoError(t, err)

	require.Equal(t, firstPEM, secondPEM, "CA must be reused, not regenerated, on repeat install")
	require.Contains(t, stdout, "Using existing CA")
}

func TestCAUninstall_RemovesTrustAnchorOnly(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	_, _, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)

	stdout, _, err := runCACmd(t, []string{"uninstall"}, caDir, trustDir)
	require.NoError(t, err)

	_, statErr := os.Stat(filepath.Join(trustDir, "postern.crt"))
	require.True(t, os.IsNotExist(statErr), "trust anchor should be removed")

	_, statErr = os.Stat(filepath.Join(caDir, "ca.pem"))
	require.NoError(t, statErr, "CA pem must be preserved without --purge")

	require.Contains(t, stdout, "Removed trust anchor")
	require.NotContains(t, stdout, "deleted CA files")
}

func TestCAUninstall_Purge_RemovesCAFiles(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	_, _, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)

	stdout, _, err := runCACmd(t, []string{"uninstall", "--purge"}, caDir, trustDir)
	require.NoError(t, err)

	_, statErr := os.Stat(filepath.Join(caDir, "ca.pem"))
	require.True(t, os.IsNotExist(statErr), "--purge must delete ca.pem")

	_, statErr = os.Stat(filepath.Join(caDir, "ca.key"))
	require.True(t, os.IsNotExist(statErr), "--purge must delete ca.key")

	require.Contains(t, stdout, "deleted CA files")
}

func TestCAUninstall_PurgeWhenAbsentIsNoOp(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	// Never installed → uninstall --purge should still succeed.
	_, _, err := runCACmd(t, []string{"uninstall", "--purge"}, caDir, trustDir)
	require.NoError(t, err)
}

func TestCAUninstall_RepeatIsIdempotent(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	_, _, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)

	_, _, err = runCACmd(t, []string{"uninstall"}, caDir, trustDir)
	require.NoError(t, err)
	_, _, err = runCACmd(t, []string{"uninstall"}, caDir, trustDir)
	require.NoError(t, err)
}

func TestCAInstall_StdoutNeverShowsPrivateKey(t *testing.T) {
	t.Parallel()
	caDir := t.TempDir()
	trustDir := t.TempDir()

	stdout, stderr, err := runCACmd(t, []string{"install"}, caDir, trustDir)
	require.NoError(t, err)

	require.False(t, strings.Contains(stdout, "PRIVATE KEY"),
		"CLI must never echo private key material")
	require.False(t, strings.Contains(stderr, "PRIVATE KEY"),
		"CLI must never echo private key material")
}
