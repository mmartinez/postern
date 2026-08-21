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
			name:             "double trailing dot is not canonicalized away",
			host:             "api.anthropic.com..:443",
			shouldIntercept:  matchAnthropic,
			blockNonBrokered: true,
			want:             modeReject,
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
