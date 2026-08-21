package broker_test

import (
	"testing"

	"github.com/mmartinez/postern/internal/broker"
)

// TestRuleMatch exercises the literal and single-* glob forms accepted by
// the config validator (config.isValidHostPattern). Glob semantics follow
// the TLS-wildcard convention: a single "*" matches exactly one DNS label
// (no dots). Apex hosts do not match a glob — "*.example.com" excludes
// "example.com" itself.
func TestRuleMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{"literal exact", "api.anthropic.com", "api.anthropic.com", true},
		{"literal mismatch", "api.anthropic.com", "api.openai.com", false},
		{"literal does not prefix-match", "api.anthropic.com", "evilapi.anthropic.com", false},
		{"literal does not suffix-match", "api.anthropic.com", "api.anthropic.com.evil.tld", false},
		{"literal is case-insensitive (host casing)", "api.anthropic.com", "API.Anthropic.Com", true},
		{"literal is case-insensitive (pattern casing)", "API.Anthropic.Com", "api.anthropic.com", true},

		{"glob single label", "*.googleapis.com", "translate.googleapis.com", true},
		{"glob excludes apex", "*.example.com", "example.com", false},
		{"glob excludes deeper subdomain", "*.example.com", "a.b.example.com", false},
		{"glob mismatched suffix", "*.example.com", "example.org", false},
		{"glob empty label rejected", "*.example.com", ".example.com", false},
		{"glob case-insensitive", "*.GOOGLEAPIS.com", "Translate.googleapis.COM", true},

		// RFC 3986 §3.2.2 lets a client send a host with one trailing dot
		// ("api.example.com." is the fully-qualified spelling of
		// "api.example.com"), and both curl and Go's net/http put the dotted
		// authority on the wire verbatim. Match canonicalizes by stripping
		// exactly one trailing dot from each side so the two spellings are
		// the same host; more than one dot is a malformed name, not an FQDN.
		{"literal matches trailing-dot FQDN host", "api.example.com", "api.example.com.", true},
		{"literal pattern with trailing dot matches undotted host", "api.example.com.", "api.example.com", true},
		{"wildcard matches trailing-dot FQDN", "*.example.com", "api.example.com.", true},
		{"only one trailing dot is stripped", "api.example.com", "api.example.com..", false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := broker.Rule{Host: tc.pattern}
			if got := r.Match(tc.host); got != tc.want {
				t.Fatalf("Rule{Host:%q}.Match(%q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
			}
		})
	}
}
