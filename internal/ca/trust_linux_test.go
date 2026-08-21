//go:build linux

package ca_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

func TestDefaultTrustDir_UsesXDGLocation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir, err := ca.DefaultTrustDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".local", "share", "ca-certificates"), dir)
}

func TestInstallAndUninstallTrust_UsesXDGUserDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	c := fixtureCA(t)

	path, err := ca.InstallTrust(c.CertPEM)
	require.NoError(t, err)
	require.Equal(t,
		filepath.Join(home, ".local", "share", "ca-certificates", "postern.crt"),
		path)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, c.CertPEM, got)

	_, revoked, err := ca.UninstallTrust()
	require.NoError(t, err)
	require.Empty(t, revoked)
	_, statErr := os.Stat(path)
	require.True(t, os.IsNotExist(statErr))
}
