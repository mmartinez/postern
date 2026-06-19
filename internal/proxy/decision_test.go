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
