// Package broker implements the request-time credential broker: matching
// outbound HTTPS requests against host rules, resolving the matched rule's
// secret reference, and injecting the credential before the proxy forwards
// the request upstream.
package broker

import "strings"

// Rule is the runtime representation of a single host-broker entry. It is
// derived from config.Rule by callers (typically the runtime wiring).
type Rule struct {
	// Host is the host pattern: either a literal hostname ("api.example.com")
	// or a single-* glob in the form "*.example.com". Validated upstream by
	// config.isValidHostPattern, so Match assumes the pattern is well-formed.
	Host string

	// SecretRef is the vendor-agnostic secret reference URI the resolver
	// looks up when this rule matches an outbound request (e.g.,
	// "op://Agents/Anthropic/api_key"). Validated upstream against the
	// secret-reference URI grammar.
	SecretRef string

	// Injection describes how the resolved credential is attached to the
	// outbound request. See InjectSpec and Rule.Inject.
	Injection InjectSpec
}

// usesBodySurface reports whether the rule rewrites the request body. The hook
// uses this to decide whether to buffer (and size-bound) the body before
// injecting; rules that don't touch the body stream their bodies untouched.
func (r Rule) usesBodySurface() bool {
	if r.Injection.Type != InjectPlaceholder {
		return false
	}
	for _, s := range r.Injection.Surfaces {
		if s == SurfaceBody {
			return true
		}
	}
	return false
}

// Match reports whether the rule's host pattern matches host. Comparison is
// case-insensitive (DNS hostnames are case-insensitive per RFC 4343). The
// glob form follows TLS-wildcard semantics: "*" matches exactly one DNS
// label and never crosses a dot, so "*.example.com" matches
// "api.example.com" but neither "example.com" nor "a.b.example.com".
//
// host should be the bare hostname without a port. Callers that hold a
// host:port value (e.g. CONNECT targets) must strip the port first.
func (r Rule) Match(host string) bool {
	pattern := strings.ToLower(r.Host)
	h := strings.ToLower(host)

	if !strings.HasPrefix(pattern, "*.") {
		return pattern == h
	}

	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(h, suffix) {
		return false
	}
	label := h[:len(h)-len(suffix)]
	if label == "" {
		return false
	}
	return !strings.Contains(label, ".")
}
