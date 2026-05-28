package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

func TestWriteDefault_CreatesDirAndFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "nested", "subdir", "config.yaml")

	require.NoError(t, config.WriteDefault(target, false))

	info, err := os.Stat(target)
	require.NoError(t, err)
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("config file mode = %o, want 0o600", got)
	}

	parent, err := os.Stat(filepath.Dir(target))
	require.NoError(t, err)
	if !parent.IsDir() {
		t.Errorf("parent should be a directory")
	}
}

func TestWriteDefault_RefusesOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(target, []byte("preserved\n"), 0o600))

	err := config.WriteDefault(target, false)
	require.Error(t, err)
	require.ErrorIs(t, err, config.ErrConfigExists)

	raw, err := os.ReadFile(target) //nolint:gosec // test path
	require.NoError(t, err)
	require.Equal(t, "preserved\n", string(raw), "file must be untouched on refusal")
}

func TestWriteDefault_ForceOverwrites(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(target, []byte("OLD\n"), 0o600))

	require.NoError(t, config.WriteDefault(target, true))

	raw, err := os.ReadFile(target) //nolint:gosec // test path
	require.NoError(t, err)
	require.NotEqual(t, "OLD\n", string(raw), "force must overwrite")
	require.Contains(t, string(raw), "postern configuration")
}

func TestWriteDefault_EmptyPath(t *testing.T) {
	t.Parallel()
	err := config.WriteDefault("", false)
	require.Error(t, err)
	if errors.Is(err, config.ErrConfigExists) {
		t.Errorf("empty-path error should not be ErrConfigExists; got %v", err)
	}
}

func TestDefaultYAML_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()

	a := config.DefaultYAML()
	b := config.DefaultYAML()
	require.Equal(t, a, b)

	a[0] = 'X'
	c := config.DefaultYAML()
	require.NotEqual(t, byte('X'), c[0], "mutating one copy must not affect the embedded source")
}
