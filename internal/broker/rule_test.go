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
//
// Match is a pure canonical-to-canonical comparison: rule patterns are
// canonicalized once at construction (FromConfigRules strips one trailing
// dot), and request hosts are canonicalized exactly once at their entry
// boundary (the proxy's CONNECT decision, the broker hook). Match itself
// performs no host transformation — canonicalization must be
// single-application, or a malformed double-dot authority survives one
// strip at the boundary and a second strip inside Match and brokers after
// all (the Greptile P1 on PR #73).
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

		// RFC 3986 §3.2.2 trailing-dot forms are normalized before Match is
		// reached, never inside it. A dotted host arriving here un-normalized
		// must not match, and a double-dot host must never match anything:
		// one boundary strip turns "api.example.com.." into "api.example.com.",
		// which is a malformed name, not the brokered host.
		{"dotted FQDN host does not match at Match level", "api.example.com", "api.example.com.", false},
		{"wildcard does not match dotted host at Match level", "*.example.com", "api.example.com.", false},
		{"double-dot host never matches", "api.example.com", "api.example.com..", false},
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
