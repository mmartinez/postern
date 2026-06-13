package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// ProviderFacts carries the registry-derived data the brand-agnostic config
// package needs to validate provider references without importing the
// credstore registry. The CLI builds it from the process-wide registry and
// the parsed config; a nil map disables the corresponding check.
type ProviderFacts struct {
	// KnownProviders is the set of provider names the binary has linked in.
	// A non-synthesized credstore naming a provider outside this set is an
	// error. A nil map disables the check.
	KnownProviders map[string]bool
	// ConfiguredSchemes is the set of secret-ref schemes the config's
	// credstores resolve to. A rule whose secret_ref scheme is outside this
	// set can never be brokered. A nil map disables the check.
	ConfiguredSchemes map[string]bool
	// ValidateSettings checks a credstore's provider-interpreted settings
	// map offline (no token, no network), returning an error for an unknown
	// key or malformed value. ValidateProviders calls it per credstore whose
	// provider is known and emits a line-numbered error at
	// credstores[i].settings. A nil func disables the check. The CLI wires
	// it to the registry so config stays decoupled from the credstore
	// provider implementations.
	ValidateSettings func(provider string, settings map[string]string) error
}

// ProviderFactsFunc derives ProviderFacts from the parsed and normalized
// config. It runs after parsing so it can inspect cfg.CredStores — including
// any synthesized legacy default — and before provider validation. The CLI
// supplies it so the credstore registry stays out of the config package.
type ProviderFactsFunc func(*Config) ProviderFacts

// ValidateProviders flags credstores that name an unknown provider and rules
// whose secret_ref scheme no configured credstore can resolve. root supplies
// line numbers; pass nil to omit locations. Each check is skipped when its
// corresponding facts map is nil, so the schema-only validation path can pass
// a zero ProviderFacts and see no provider lints.
func ValidateProviders(cfg *Config, root *yaml.Node, facts ProviderFacts) []LintError {
	if cfg == nil {
		return nil
	}
	v := newValidator(root)

	if facts.KnownProviders != nil {
		for i := range cfg.CredStores {
			c := &cfg.CredStores[i]
			// Synthesized credstores carry no user-authored provider name;
			// the runtime late-binds them to the legacy default scheme.
			if c.IsSynthesized() || c.Provider == "" {
				continue
			}
			if !facts.KnownProviders[c.Provider] {
				v.add(fmt.Sprintf("credstores[%d].provider", i),
					fmt.Sprintf("unknown provider %q (no credstore provider is registered under that name)", c.Provider),
					SeverityError)
			}
		}
	}

	if facts.ValidateSettings != nil {
		for i := range cfg.CredStores {
			c := &cfg.CredStores[i]
			if c.IsSynthesized() || c.Provider == "" {
				continue
			}
			// A provider already flagged as unknown above can't have its
			// settings validated, and a second lint on the same entry is
			// noise.
			if facts.KnownProviders != nil && !facts.KnownProviders[c.Provider] {
				continue
			}
			if err := facts.ValidateSettings(c.Provider, c.Settings); err != nil {
				v.add(fmt.Sprintf("credstores[%d].settings", i), err.Error(), SeverityError)
			}
		}
	}

	if facts.ConfiguredSchemes != nil {
		for i := range cfg.Rules {
			r := cfg.Rules[i]
			v.checkRefScheme(fmt.Sprintf("rules[%d].secret_ref", i), r.SecretRef, facts)
			// An oauth1 rule carries its credential refs in the inject block, not
			// the rule-level secret_ref; check those schemes too so an unroutable
			// oauth1 ref fails at validate/boot rather than at the first request.
			if r.Inject.Type == InjectTypeOAuth1 {
				v.checkRefScheme(fmt.Sprintf("rules[%d].inject.consumer_key_ref", i), r.Inject.ConsumerKeyRef, facts)
				v.checkRefScheme(fmt.Sprintf("rules[%d].inject.consumer_secret_ref", i), r.Inject.ConsumerSecretRef, facts)
				v.checkRefScheme(fmt.Sprintf("rules[%d].inject.token_ref", i), r.Inject.TokenRef, facts)
				v.checkRefScheme(fmt.Sprintf("rules[%d].inject.token_secret_ref", i), r.Inject.TokenSecretRef, facts)
			}
		}
		// The `postern exec` env: values resolve through the same credstores; an
		// unroutable scheme there is the same fail-at-validate condition as a rule.
		for _, name := range sortedKeys(cfg.Env) {
			v.checkRefScheme("env."+name, cfg.Env[name], facts)
		}
	}

	return v.out
}

// checkRefScheme flags a secret_ref at path whose scheme has no configured
// credstore. An empty or malformed ref is skipped: the schema validator already
// covers those, and a second lint on the same line is noise.
func (v *validator) checkRefScheme(path, ref string, facts ProviderFacts) {
	scheme, _, ok := strings.Cut(ref, "://")
	if !ok || scheme == "" {
		return
	}
	if !facts.ConfiguredSchemes[scheme] {
		v.add(path, fmt.Sprintf("no credstore configured for secret_ref scheme %q", scheme), SeverityError)
	}
}
