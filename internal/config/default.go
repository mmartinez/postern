package config

import (
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

//go:embed default.yaml
var defaultYAML []byte

// ErrConfigExists is returned by WriteDefault when the target file is already
// present and overwrite was not requested.
var ErrConfigExists = errors.New("config file already exists; pass --force to overwrite")

// DefaultYAML returns the embedded default config (~/.postern/config.yaml)
// template. Callers must not mutate the returned slice.
func DefaultYAML() []byte {
	// Copy to keep the embedded backing array immutable from callers.
	out := make([]byte, len(defaultYAML))
	copy(out, defaultYAML)
	return out
}

// WriteDefault writes the embedded default config to path. The parent
// directory is created with 0o700 if missing. If the file already exists,
// it returns ErrConfigExists unless force is true.
func WriteDefault(path string, force bool) error {
	if path == "" {
		return errors.New("config path must not be empty")
	}

	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%w: %s", ErrConfigExists, path)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("stat config path: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	if err := os.WriteFile(path, DefaultYAML(), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
