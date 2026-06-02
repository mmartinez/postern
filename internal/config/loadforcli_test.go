package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

func TestLoadForCLI_ValidFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, config.DefaultYAML(), 0o600))

	cfg, err := config.LoadForCLI(path, true)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.Equal(t, "127.0.0.1:1701", cfg.Proxy.Listen)
}

func TestLoadForCLI_MissingOptional(t *testing.T) {
	t.Parallel()

	cfg, err := config.LoadForCLI(filepath.Join(t.TempDir(), "absent.yaml"), false)
	require.NoError(t, err)
	require.Nil(t, cfg)
}

func TestLoadForCLI_MissingRequired(t *testing.T) {
	t.Parallel()

	absent := filepath.Join(t.TempDir(), "absent.yaml")
	cfg, err := config.LoadForCLI(absent, true)
	require.Nil(t, cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrNotExist)
	require.Contains(t, err.Error(), "load config")
}

func TestLoadForCLI_FatalLintIsError(t *testing.T) {
	t.Parallel()

	doc := strings.Replace(validConfig, "on_no_match: passthrough", "on_no_match: explode", 1)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	cfg, err := config.LoadForCLI(path, true)
	require.Nil(t, cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "schema error")
	require.Contains(t, err.Error(), "postern config validate")
}

func TestLoadForCLI_NoPlaceholderTemplateIsRejected(t *testing.T) {
	t.Parallel()

	// A template without a {{ CREDENTIAL }} placeholder is a fail-open config
	// (the credential is discarded and the request forwarded unauthenticated),
	// so LoadForCLI must reject it rather than let the server boot.
	doc := strings.Replace(validConfig, `"{{ CREDENTIAL }}"`, `"static-value"`, 1)
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	cfg, err := config.LoadForCLI(path, true)
	require.Nil(t, cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "schema error")
}

func TestLoadForCLI_EmptyPathResolvesDefault(t *testing.T) {
	// Not parallel: mutates HOME via t.Setenv so DefaultPath resolves into a
	// known temp dir. required=true turns the missing default into an error
	// whose message must name the resolved default path.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := config.LoadForCLI("", true)
	require.Error(t, err)
	require.Contains(t, err.Error(), filepath.Join(tmp, ".postern", "config.yaml"))
}

func TestDefaultPath(t *testing.T) {
	// Not parallel: mutates HOME via t.Setenv.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	require.Equal(t, filepath.Join(tmp, ".postern", "config.yaml"), config.DefaultPath())
}
