package proxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecideConnect(t *testing.T) {
	t.Parallel()

	matchAnthropic := func(host string) bool { return host == "api.anthropic.com" }

	tests := []struct {
		name             string
		host             string
		shouldIntercept  func(string) bool
		blockNonBrokered bool
		want             connectMode
	}{
		{
			name:            "brokered host is intercepted",
			host:            "api.anthropic.com:443",
			shouldIntercept: matchAnthropic,
			want:            modeMITM,
		},
		{
			name:            "brokered match strips the port before matching",
			host:            "api.anthropic.com:8443",
			shouldIntercept: matchAnthropic,
			want:            modeMITM,
		},
		{
			name:            "non-brokered host tunnels by default",
			host:            "example.com:443",
			shouldIntercept: matchAnthropic,
			want:            modeTunnel,
		},
		{
			name:             "non-brokered host is rejected when blocking",
			host:             "example.com:443",
			shouldIntercept:  matchAnthropic,
			blockNonBrokered: true,
			want:             modeReject,
		},
		{
			// RFC 3986 §3.2.2: "api.anthropic.com." is the fully-qualified
			// spelling of "api.anthropic.com"; curl and Go's net/http both
			// put the dotted authority on the wire verbatim. The decision
			// boundary must canonicalize it or brokered hosts tunnel (or,
			// under block, get rejected) on a syntactic difference.
			name:            "trailing-dot FQDN target is intercepted",
			host:            "api.anthropic.com.:443",
			shouldIntercept: matchAnthropic,
			want:            modeMITM,
		},
		{
			// Canonicalization is single-application: one strip turns the
			// malformed double-dot authority into "api.anthropic.com.", which
			// is not a brokered host. It must fall through to policy — never
			// be MITM'd — no matter what downstream matchers do.
			name:             "double trailing dot is not canonicalized away (block)",
			host:             "api.anthropic.com..:443",
			shouldIntercept:  matchAnthropic,
			blockNonBrokered: true,
			want:             modeReject,
		},
		{
			name:             "double trailing dot tunnels untouched under passthrough",
			host:             "api.anthropic.com..:443",
			shouldIntercept:  matchAnthropic,
			blockNonBrokered: false,
			want:             modeTunnel,
		},
		{
			name:            "nil shouldIntercept intercepts everything (back-compat)",
			host:            "example.com:443",
			shouldIntercept: nil,
			want:            modeMITM,
		},
		{
			name:             "nil shouldIntercept intercepts even when blocking is set",
			host:             "example.com:443",
			shouldIntercept:  nil,
			blockNonBrokered: true,
			want:             modeMITM,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := decideConnect(tc.host, tc.shouldIntercept, tc.blockNonBrokered)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestCanonicalHost_IdempotentForWellFormedHosts pins the single-application
// property the decision path depends on: for any well-formed input (bare or
// single trailing dot) re-canonicalizing is a no-op, so a host crossing
// several boundaries cannot be stripped dot by dot into a matchable name.
// (A malformed double-dot input is deliberately NOT idempotent — each
// boundary strips at most one dot, and the residue must stay malformed.)
func TestCanonicalHost_IdempotentForWellFormedHosts(t *testing.T) {
	t.Parallel()

	for _, h := range []string{"api.example.com", "api.example.com.", "API.Example.Com."} {
		once := canonicalHost(h)
		require.Equal(t, once, canonicalHost(once),
			"canonicalHost must be idempotent for well-formed host %q", h)
	}
	require.Equal(t, "api.example.com.", canonicalHost("api.example.com.."),
		"at most one trailing dot may be stripped per application")
}
