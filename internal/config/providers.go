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
	// SchemeNames maps each secret-ref scheme to the names of the
	// configured credstores resolving it. An unqualified ref whose scheme
	// lists more than one name is ambiguous (the ref must carry a
	// `<scheme>+<name>` qualifier); a scheme with no entry is unroutable.
	// Together with ClassifyRef it drives the credstore-qualified-ref checks
	// (see validator_credstore.go). A nil map disables those checks.
	SchemeNames map[string][]string
	// StoreSchemes maps each configured credstore name to its provider's
	// secret-ref URI scheme, backing the check that a qualified ref's
	// scheme matches the named store's provider. A nil map disables that
	// check.
	StoreSchemes map[string]string
	// ClassifyRef parses a secret reference into its scheme and optional
	// credstore-name qualifier per the `<scheme>+<name>://` grammar. The CLI
	// wires it to credstore.ParseQualifiedRef so the config package stays
	// decoupled from the credstore registry (which imports this package).
	// A nil func makes every reference be treated as unqualified by the
	// scheme checks.
	ClassifyRef func(secretRef string) (scheme, name string, ok bool)
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
	}

	// Credstore-qualified-ref routing checks (ambiguity, unknown store,
	// scheme mismatch). They need the registry-derived routing picture, so
	// they live on this facts-driven stage rather than schema validation;
	// see validator_credstore.go. Route refs are checked here too — the
	// schema-only pass never sees their scheme.
	if facts.SchemeNames != nil && facts.ClassifyRef != nil {
		for i := range cfg.Rules {
			r := cfg.Rules[i]
			base := fmt.Sprintf("rules[%d]", i)
			v.checkQualifiedRef(base+".secret_ref", r.SecretRef, facts)
			for j, rt := range r.Routes {
				v.checkQualifiedRef(fmt.Sprintf("%s.routes[%d].secret_ref", base, j), rt.SecretRef, facts)
			}
			if r.Inject.Type == InjectTypeOAuth1 {
				v.checkQualifiedRef(base+".inject.consumer_key_ref", r.Inject.ConsumerKeyRef, facts)
				v.checkQualifiedRef(base+".inject.consumer_secret_ref", r.Inject.ConsumerSecretRef, facts)
				v.checkQualifiedRef(base+".inject.token_ref", r.Inject.TokenRef, facts)
				v.checkQualifiedRef(base+".inject.token_secret_ref", r.Inject.TokenSecretRef, facts)
			}
		}
	}

	return v.out
}

// checkRefScheme flags a secret_ref at path whose scheme has no configured
// credstore. An empty or malformed ref is skipped: the schema validator already
// covers those, and a second lint on the same line is noise. When the facts
// carry the shared qualified-ref parser, a `<scheme>+<name>://` qualifier is
// stripped first so the scheme compared against ConfiguredSchemes is the
// provider's plain scheme.
func (v *validator) checkRefScheme(path, ref string, facts ProviderFacts) {
	var scheme string
	if facts.ClassifyRef != nil {
		var ok bool
		scheme, _, ok = facts.ClassifyRef(ref)
		if !ok {
			return
		}
	} else {
		var ok bool
		scheme, _, ok = strings.Cut(ref, "://")
		if !ok || scheme == "" {
			return
		}
	}
	if !facts.ConfiguredSchemes[scheme] {
		v.add(path, fmt.Sprintf("no credstore configured for secret_ref scheme %q", scheme), SeverityError)
	}
}
