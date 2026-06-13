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
	// InjectTypeOAuth1 signs the request with OAuth 1.0a (HMAC-SHA1) and sets
	// the Authorization: OAuth header. It uses the four oauth1 *_ref fields on
	// Inject instead of a rule-level secret_ref/template.
	InjectTypeOAuth1 InjectType = "oauth1"
)

// InjectSurface names a request component placeholder substitution can rewrite.
// Surfaces are opt-in per rule via inject.in; the default is header-only.
type InjectSurface string

// Injection surface values accepted in YAML.
const (
	InjectSurfaceHeader InjectSurface = "header"
	InjectSurfaceBody   InjectSurface = "body"
	InjectSurfacePath   InjectSurface = "path"
	InjectSurfaceQuery  InjectSurface = "query"
)

// DefaultMaxBodyBytes is the proxy-wide body buffering cap used when
// proxy.max_body_bytes is unset (or non-positive). A request body that a
// body-rewriting rule would buffer beyond this size is rejected with 413.
const DefaultMaxBodyBytes = 1 << 20 // 1 MiB

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

	// Env maps environment-variable names to secret references for the
	// `postern exec` command, which resolves each value through the same
	// credstore path the proxy uses and exports it into the launched child's
	// environment. It is independent of the proxy's rules: a config may set
	// env, rules, or both. Each value is a <scheme>://<rest> secret_ref whose
	// scheme a configured credstore must resolve.
	Env map[string]string `yaml:"env,omitempty"`
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

	// RefreshToken is an optional second credential source for providers that
	// need two secrets — currently the OAuth2 refresh_token grant, which
	// authenticates with the client secret (Token) plus a long-lived refresh
	// token (this). It is resolved through the same token chain as Token. A
	// provider that does not implement credstore.SecondarySecretProvider rejects
	// it at boot; the validator requires it iff settings.grant_type is
	// refresh_token.
	RefreshToken Token `yaml:"refresh_token,omitempty"`

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
	Listen string `yaml:"listen"`
	// CacheTTL is the legacy scalar credential-cache TTL. It is retained for
	// backward compatibility and is an alias for Cache.TTL; new configs should
	// use the cache block. See Proxy.CacheSettings for how the two interact.
	CacheTTL  time.Duration `yaml:"cache_ttl,omitempty"`
	Cache     *Cache        `yaml:"cache,omitempty"`
	OnNoMatch OnNoMatch     `yaml:"on_no_match"`

	// MaxBodyBytes caps how much of a request body postern buffers when a
	// rule rewrites the body (inject.in includes "body"). Zero means use
	// DefaultMaxBodyBytes. A body larger than the cap is rejected with 413.
	// Bound at startup; a hot-reload edit warns and does not take effect.
	MaxBodyBytes int `yaml:"max_body_bytes,omitempty"`
}

// Default cache settings applied when the corresponding key is absent. The
// defaults are tuned for long-lived API tokens: refresh well before expiry and
// tolerate a long vault outage by serving the last-known-good value.
const (
	// DefaultCacheTTL is the nominal freshness window when neither cache.ttl
	// nor the legacy cache_ttl is set.
	DefaultCacheTTL = time.Hour
	// DefaultCacheMaxStale bounds how long a value is served after it could
	// last be refreshed, before the resolver fails closed.
	DefaultCacheMaxStale = 24 * time.Hour
)

// Cache is the optional proxy.cache block: a background-refreshing credential
// cache. Every field is optional; absent values default per
// Proxy.CacheSettings. The effective settings must satisfy
// 0 < refresh_ahead < ttl <= max_stale (enforced by the validator).
type Cache struct {
	// TTL is the nominal freshness window. Past TTL a value is served stale
	// (up to MaxStale) while a refresh is attempted.
	TTL time.Duration `yaml:"ttl,omitempty"`
	// RefreshAhead is the age at which a request triggers an asynchronous
	// refresh; defaults to 75% of the effective TTL.
	RefreshAhead time.Duration `yaml:"refresh_ahead,omitempty"`
	// MaxStale is the hard age limit; past it the resolver fails closed rather
	// than serve a value. Defaults to DefaultCacheMaxStale (clamped up to TTL).
	MaxStale time.Duration `yaml:"max_stale,omitempty"`
}

// CacheSettings is the resolved, effective credential-cache configuration the
// runtime builds its resolver cache from.
type CacheSettings struct {
	TTL          time.Duration
	RefreshAhead time.Duration
	MaxStale     time.Duration
}

// CacheSettings resolves the effective cache configuration from the cache block
// and the legacy cache_ttl alias, applying defaults. It assumes the config has
// passed validation and clamps defensively so the result always satisfies
// 0 < RefreshAhead < TTL <= MaxStale.
//
// Precedence: cache.ttl wins over cache_ttl (the validator rejects the case
// where both are set and disagree); when neither is set, DefaultCacheTTL.
// refresh_ahead defaults to 75% of the effective TTL; max_stale defaults to
// DefaultCacheMaxStale, clamped up to TTL.
func (p Proxy) CacheSettings() CacheSettings {
	ttl := DefaultCacheTTL
	switch {
	case p.Cache != nil && p.Cache.TTL > 0:
		ttl = p.Cache.TTL
	case p.CacheTTL > 0:
		ttl = p.CacheTTL
	}

	refreshAhead := ttl - ttl/4 // 75% of ttl
	if p.Cache != nil && p.Cache.RefreshAhead > 0 {
		refreshAhead = p.Cache.RefreshAhead
	}
	if refreshAhead <= 0 || refreshAhead >= ttl {
		refreshAhead = ttl - ttl/4
	}

	maxStale := DefaultCacheMaxStale
	if p.Cache != nil && p.Cache.MaxStale > 0 {
		maxStale = p.Cache.MaxStale
	}
	if maxStale < ttl {
		maxStale = ttl
	}

	return CacheSettings{TTL: ttl, RefreshAhead: refreshAhead, MaxStale: maxStale}
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

	// Routes turns a single host rule into a placeholder-routing rule: each
	// entry's token both selects, and is replaced by, its own secret. Mutually
	// exclusive with the rule-level SecretRef and inject.name, and valid only
	// with inject.type=placeholder. Lets several agents share one host rule,
	// each presenting its own token.
	Routes []Route `yaml:"routes,omitempty"`
}

// Route is one entry of a placeholder-routing rule. Token is the placeholder an
// agent presents on a declared inject surface; matching it selects SecretRef as
// the secret to resolve, and the same token is replaced in place by the
// resolved value. Name is an operator-facing label surfaced in logs to
// attribute a request to an agent; the token value itself is never logged.
type Route struct {
	Name      string `yaml:"name"`
	Token     string `yaml:"token"`
	SecretRef string `yaml:"secret_ref"`
}

// Inject describes how a resolved credential is attached to outbound traffic.
type Inject struct {
	Type     InjectType `yaml:"type"`
	Name     string     `yaml:"name,omitempty"`
	Template string     `yaml:"template"`

	// In lists the request surfaces placeholder mode rewrites (any subset of
	// header, body, path, query). Empty means header-only. Valid only with
	// type: placeholder.
	In []InjectSurface `yaml:"in,omitempty"`

	// MaxBodyBytes overrides proxy.max_body_bytes for this rule's body
	// buffering. Zero means inherit the proxy-wide cap. Meaningful only when
	// In includes "body".
	MaxBodyBytes *int `yaml:"max_body_bytes,omitempty"`

	// OAuth 1.0a (inject.type: oauth1) credential references. All four are
	// required for, and valid only with, the oauth1 type; each is a secret_ref
	// URI resolved through the normal credstore path. They replace the
	// rule-level secret_ref and the header/template fields.
	ConsumerKeyRef    string `yaml:"consumer_key_ref,omitempty"`
	ConsumerSecretRef string `yaml:"consumer_secret_ref,omitempty"`
	TokenRef          string `yaml:"token_ref,omitempty"`
	TokenSecretRef    string `yaml:"token_secret_ref,omitempty"`
}
