package ca_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

func TestDefaultDir_UsesHomeEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir, err := ca.DefaultDir()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home, ".postern"), dir)
}

func TestCertPath_JoinsCAFilename(t *testing.T) {
	t.Parallel()
	require.Equal(t, filepath.Join("/foo", "ca.pem"), ca.CertPath("/foo"))
}
