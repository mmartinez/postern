// Package config defines the postern YAML configuration schema and provides
// loading, validating, and (in T7) hot-reload primitives.
//
// The schema is the source of truth: every field that affects runtime
// behavior must be declared on one of the types below.
package config

import "time"

// TokenSource pins one step in the token resolution chain (SPEC §8).
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
type Config struct {
	Token Token  `yaml:"token"`
	Proxy Proxy  `yaml:"proxy"`
	Rules []Rule `yaml:"rules"`
}

// Token controls how postern obtains the credential vendor service-account
// token at startup. See SPEC §8 token resolution chain.
type Token struct {
	Source          TokenSource `yaml:"source"`
	EnvVar          string      `yaml:"env_var"`
	File            string      `yaml:"file"`
	KeychainAccount string      `yaml:"keychain_account"`
}

// Proxy is the listener + caching configuration for the forward HTTPS proxy.
type Proxy struct {
	Listen    string        `yaml:"listen"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`
	OnNoMatch OnNoMatch     `yaml:"on_no_match"`
}

// Rule is a single host-matching credential broker entry.
type Rule struct {
	Host      string `yaml:"host"`
	SecretRef string `yaml:"secret_ref"`
	Inject    Inject `yaml:"inject"`
}

// Inject describes how a resolved credential is attached to outbound traffic.
type Inject struct {
	Type     InjectType `yaml:"type"`
	Name     string     `yaml:"name,omitempty"`
	Template string     `yaml:"template"`
}
