package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Load parses YAML from r into a Config and returns both the typed value and
// the raw AST root for line-number-bearing validation. Unknown YAML fields
// cause an error (strict mode).
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
//
// Template expansion runs before validation so the validator sees the
// effective rule (template defaults merged with user overrides). Unknown
// template names are surfaced as their own LintError alongside whatever
// the schema validator finds, with the line number pointing at the
// `template:` key.
//
// CredStore normalization runs before validation: a legacy top-level
// `token:` block (and no `credstores:`) is folded into a synthesized
// "default" credstore so the validator and the runtime always see the
// canonical multi-credstore form. Configs that set both forms are not
// normalized; the validator flags the ambiguity.
func LoadAndValidate(r io.Reader) (*Config, []LintError, error) {
	return loadAndValidate(r, nil)
}

// LoadAndValidateWithProviders is LoadAndValidate plus the registry-aware
// pass: it additionally flags credstores naming an unknown provider and rules
// whose secret_ref scheme no configured credstore can resolve. factsFn
// derives the registry facts from the parsed config; it runs after
// normalization so it sees any synthesized legacy-default credstore. Passing
// a nil factsFn is equivalent to LoadAndValidate.
func LoadAndValidateWithProviders(r io.Reader, factsFn ProviderFactsFunc) (*Config, []LintError, error) {
	return loadAndValidate(r, factsFn)
}

func loadAndValidate(r io.Reader, factsFn ProviderFactsFunc) (*Config, []LintError, error) {
	cfg, ast, err := Load(r)
	if err != nil {
		return nil, nil, err
	}
	var lints []LintError
	if conflict := normalizeCredStores(cfg); conflict != nil {
		lints = append(lints, *conflict)
	}
	tmplLints, skipRule := expandTemplates(cfg, ast)
	lints = append(lints, tmplLints...)
	lints = append(lints, validateSkipping(cfg, ast, skipRule)...)
	if factsFn != nil {
		lints = append(lints, ValidateProviders(cfg, ast, factsFn(cfg))...)
	}
	return cfg, lints, nil
}

// normalizeCredStores converts the legacy single-credstore form into the
// canonical multi-credstore form when possible. It returns a non-nil
// LintError when the user has set both forms (which is ambiguous);
// callers append that lint to their result and skip synthesis so the
// original cfg.Token survives for the validator to see.
//
// The synthesized credstore leaves Provider empty as a sentinel that
// means "let the runtime pick the registered provider." Keeping the
// provider name out of the config package avoids a config → credstore
// import cycle and keeps brand strings out of the file.
func normalizeCredStores(cfg *Config) *LintError {
	if cfg == nil {
		return nil
	}
	tokenSet := !cfg.Token.IsZero()
	hasCredStores := len(cfg.CredStores) > 0
	switch {
	case tokenSet && hasCredStores:
		return &LintError{
			Severity: SeverityError,
			Path:     "credstores",
			Message:  "set either top-level `token:` or `credstores:`, not both",
		}
	case tokenSet && !hasCredStores:
		cfg.CredStores = []CredStore{{
			Name:        DefaultCredStoreName,
			Token:       cfg.Token,
			synthesized: true,
		}}
		cfg.Token = Token{}
	}
	return nil
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

// DefaultPath returns the standard config location
// (~/.postern/config.yaml), falling back to ./postern.yaml when the user's
// home directory cannot be determined. CLI subcommands use it when no
// explicit --config path is given.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "postern.yaml"
	}
	return filepath.Join(home, ".postern", "config.yaml")
}

// LoadForCLI loads and schema-checks the config a CLI subcommand should act
// on. An empty path resolves to DefaultPath. When required is false a missing
// file yields (nil, nil) so the caller can fall through to a default (e.g.
// passthrough mode); when required is true a missing file is an error. A
// config carrying any SeverityError lint is rejected so a structurally broken
// file never silently takes effect; the error points the user at `postern
// config validate` for the line-numbered details.
func LoadForCLI(path string, required bool) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	cfg, lints, err := LoadFile(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("load config %s: %w", path, err)
	}
	var fatal int
	for _, l := range lints {
		if l.Severity == SeverityError {
			fatal++
		}
	}
	if fatal > 0 {
		return nil, fmt.Errorf("config %s has %d schema error(s); run `postern config validate` for details", path, fatal)
	}
	return cfg, nil
}

// LoadFileWithProviders is LoadFile plus the registry-aware validation pass.
// See LoadAndValidateWithProviders.
func LoadFileWithProviders(path string, factsFn ProviderFactsFunc) (*Config, []LintError, error) {
	f, err := os.Open(path) //nolint:gosec // user-supplied path is intentional
	if err != nil {
		return nil, nil, fmt.Errorf("open config: %w", err)
	}
	defer func() { _ = f.Close() }()
	return LoadAndValidateWithProviders(f, factsFn)
}
