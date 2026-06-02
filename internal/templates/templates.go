// Package templates ships the built-in broker presets for common APIs.
// A user who only wants to broker the conventional path for a common API
// can write `template: anthropic` in their rule instead of restating the
// host pattern, header name, and credential template. The config loader
// reads this registry and fills the rule's host + inject fields from the
// matched entry; user-supplied fields on the same rule override the
// template defaults so power users can deviate (custom header name,
// different host pattern, alternate credential format).
//
// Registry entries are intentionally a small struct of strings rather than
// a config.Inject value so this package has zero coupling to internal/config
// and avoids the import cycle that direction would create.
package templates

import (
	"sort"
	"strings"
)

// Template is one entry in the built-in registry. All fields are strings so
// the config layer can pour them into config.Rule / config.Inject without
// translating enums; the validator still has the final say on whether the
// combined rule is well-formed.
type Template struct {
	// Name is the lookup key as written in the YAML rule (`template: <name>`).
	Name string

	// Host is the default host pattern this template matches. Either a
	// literal hostname or a single-* glob (see config.isValidHostPattern).
	Host string

	// InjectType is the inject strategy keyword ("header" or "placeholder").
	// All built-ins are header-mode today; placeholder templates would be
	// added later.
	InjectType string

	// HeaderName is the header to set when InjectType == "header".
	HeaderName string

	// Template is the credential render template ("Bearer {{ CREDENTIAL }}"
	// etc.). The CREDENTIAL placeholder is substituted at request time.
	Template string
}

// builtins is the canonical registry. Names are lowercase; Lookup normalises
// the caller's input before indexing so YAML authors can write any casing.
var builtins = map[string]Template{
	"anthropic": {
		Name:       "anthropic",
		Host:       "api.anthropic.com",
		InjectType: "header",
		HeaderName: "x-api-key",
		Template:   "{{ CREDENTIAL }}",
	},
	"openai": {
		Name:       "openai",
		Host:       "api.openai.com",
		InjectType: "header",
		HeaderName: "authorization",
		Template:   "Bearer {{ CREDENTIAL }}",
	},
	"github": {
		Name:       "github",
		Host:       "api.github.com",
		InjectType: "header",
		HeaderName: "authorization",
		Template:   "Bearer {{ CREDENTIAL }}",
	},
	"stripe": {
		Name:       "stripe",
		Host:       "api.stripe.com",
		InjectType: "header",
		HeaderName: "authorization",
		Template:   "Bearer {{ CREDENTIAL }}",
	},
	"googleapis": {
		Name:       "googleapis",
		Host:       "*.googleapis.com",
		InjectType: "header",
		HeaderName: "authorization",
		Template:   "Bearer {{ CREDENTIAL }}",
	},
}

// Lookup returns the registered Template for name and reports whether one
// exists. Comparison is case-insensitive so the YAML file is permissive
// even though the canonical names are lowercase.
func Lookup(name string) (Template, bool) {
	t, ok := builtins[strings.ToLower(strings.TrimSpace(name))]
	return t, ok
}

// Names returns the sorted list of registered template names. Used by the
// config validator's "unknown template" error message so the user gets a
// stable list of valid choices.
func Names() []string {
	out := make([]string, 0, len(builtins))
	for name := range builtins {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
