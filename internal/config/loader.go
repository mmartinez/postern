package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// Load parses YAML from r into a Config and returns both the typed value and
// the raw AST root for line-number-bearing validation. Unknown YAML fields
// cause an error (strict mode per SPEC §8).
func Load(r io.Reader) (*Config, *yaml.Node, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, fmt.Errorf("read config: %w", err)
	}

	var ast yaml.Node
	if err := yaml.Unmarshal(raw, &ast); err != nil {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, &ast, nil
}

// LoadAndValidate is the one-shot entry point used by `postern config
// validate`. Returns the parsed Config, the slice of lints (errors +
// warnings) discovered by schema validation, and a non-nil error only if
// the file could not be parsed at all.
func LoadAndValidate(r io.Reader) (*Config, []LintError, error) {
	cfg, ast, err := Load(r)
	if err != nil {
		return nil, nil, err
	}
	return cfg, Validate(cfg, ast), nil
}

// LoadFile is a convenience wrapper for the CLI.
func LoadFile(path string) (*Config, []LintError, error) {
	f, err := os.Open(path) //nolint:gosec // user-supplied path is intentional
	if err != nil {
		return nil, nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()
	return LoadAndValidate(f)
}
