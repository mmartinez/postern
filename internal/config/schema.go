// Package config defines the postern YAML configuration schema and provides
// loading, validating, and hot-reload primitives.
//
// The schema is the source of truth: every field that affects runtime
// behavior must be declared on one of the types below.
package config

import "time"

// TokenSource pins one step in the token resolution chain.
// "auto" walks file → env → keychain in order.
type TokenSource string

// Token source values accepted in YAML.
const (
	TokenSourceAuto     TokenSource = "auto"
	TokenSourceKeychain TokenSource = "keychain"
	TokenSourceEnv      TokenSource = "env"
	TokenSourceFile     TokenSource = "file"
)

// OnNoMatch is the proxy behavior when an outbound request doesn't match any
// rule. The conservative default is passthrough (forward unchanged); "block"
// is for paranoid deployments that want allowlist-only egress.
type OnNoMatch string

// On-no-match behavior values accepted in YAML.
const (
	OnNoMatchPassthrough OnNoMatch = "passthrough"
	OnNoMatchBlock       OnNoMatch = "block"
)

// InjectType selects between header injection (most APIs) and
// placeholder substitution (where the agent already supplies a sentinel
// like "__placeholder__" that we replace before forwarding).
type InjectType string

// Injection type values accepted in YAML.
const (
	InjectTypeHeader      InjectType = "header"
	InjectTypePlaceholder InjectType = "placeholder"
)

// Config is the root of the YAML schema (~/.postern/config.yaml).
//
// Two top-level credential-vendor shapes are accepted, but only one at a
// time:
//
//   - Legacy single-vendor form: a top-level `token:` block; the loader
//     synthesizes an implicit "default" credstore from it at parse time.
//   - Multi-vendor form: a `credstores:` list, each entry naming its
//     vendor and token source. Top-level `token:` must be omitted in this
//     form (validation rejects mixing the two).
type Config struct {
	Token      Token       `yaml:"token,omitempty"`
	CredStores []CredStore `yaml:"credstores,omitempty"`
	Proxy      Proxy       `yaml:"proxy"`
	Rules      []Rule      `yaml:"rules"`
}

// CredStore declares a single credential vendor configuration the broker
// can route rules to. Provider must match the registered Name() of a
// credstore provider compiled into the binary. Token controls how postern
// obtains the service-account token for this credstore at boot.
//
// Name is currently only a display and uniqueness handle (surfaced in logs;
// duplicate names are a validation error). It does NOT yet disambiguate
// routing: the broker routes a rule to a credstore solely by the rule's
// secret_ref URI scheme, so scheme is the sole routing key and two credstores
// resolving to the same scheme are rejected at boot. Supporting two accounts
// of the same vendor (e.g. two op credstores) is a future change that would
// make routing key on Name and extend the secret_ref grammar to name its
// credstore; Name is kept in the schema now so that change need not break the
// config grammar.
type CredStore struct {
	Name     string `yaml:"name"`
	Provider string `yaml:"provider"`
	Token    Token  `yaml:"token"`

	// Settings carries optional, provider-interpreted configuration (e.g. a
	// self-hosted server URL). The config package treats it as an opaque
	// map to stay brand-agnostic and avoid reopening the config → credstore
	// import cycle; the provider parses and validates the keys it
	// recognizes. Per-key validation runs at `config validate` time via the
	// registry bridge, so an unknown key is a line-numbered error rather
	// than a silently ignored one.
	Settings map[string]string `yaml:"settings,omitempty"`

	// synthesized is set by the loader on the implicit credstore it
	// builds from a legacy top-level `token:` block. The field is
	// unexported so the YAML decoder cannot set it; user-authored
	// entries always have synthesized=false even if their Name and
	// Provider happen to match the synthesized shape.
	synthesized bool
}

// IsSynthesized reports whether the loader created this credstore from a
// legacy top-level `token:` block (rather than the user authoring it
// directly). Consumers outside the config package use this to apply
// late-binding (e.g., picking the canonical provider when Provider is
// empty) without conflating the marker with valid user input.
func (c CredStore) IsSynthesized() bool { return c.synthesized }

// DefaultCredStoreName is the synthetic Name assigned to the credstore
// the loader builds from a legacy top-level `token:` block. Surfaced in
// logs and exposed to tests; not part of the YAML grammar.
const DefaultCredStoreName = "default"

// Token controls how postern obtains the credential vendor service-account
// token at startup, via the token resolution chain.
type Token struct {
	Source          TokenSource `yaml:"source"`
	EnvVar          string      `yaml:"env_var"`
	File            string      `yaml:"file"`
	KeychainAccount string      `yaml:"keychain_account"`
}

// IsZero reports whether t is the YAML zero value. Used by the loader to
// detect the legacy "top-level token:" form and to validate that the
// legacy form is not used in combination with the multi-credstore form.
func (t Token) IsZero() bool {
	return t.Source == "" && t.EnvVar == "" && t.File == "" && t.KeychainAccount == ""
}

// Proxy is the listener + caching configuration for the forward HTTPS proxy.
type Proxy struct {
	Listen    string        `yaml:"listen"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`
	OnNoMatch OnNoMatch     `yaml:"on_no_match"`
}

// DefaultListenAddr is the loopback bind postern uses when no listen address
// is configured. It is the schema-level default for Proxy.Listen: the CLI
// uses it as the --addr flag default and as bootstrap's fallback. The
// embedded default.yaml carries the same literal as the YAML source of truth.
const DefaultListenAddr = "127.0.0.1:1701"

// Rule is a single host-matching credential broker entry.
//
// Template names a built-in preset from internal/templates (e.g.
// "anthropic"); when set, the loader fills any blank Host or Inject field
// from the registry entry. User-supplied fields on the same rule always
// take precedence over the template defaults, so overrides are explicit.
type Rule struct {
	Template  string `yaml:"template,omitempty"`
	Host      string `yaml:"host,omitempty"`
	SecretRef string `yaml:"secret_ref"`
	Inject    Inject `yaml:"inject,omitempty"`
}

// Inject describes how a resolved credential is attached to outbound traffic.
type Inject struct {
	Type     InjectType `yaml:"type"`
	Name     string     `yaml:"name,omitempty"`
	Template string     `yaml:"template"`
}
