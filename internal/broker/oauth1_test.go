package broker

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOAuth1AuthHeader_KnownAnswerVector pins the signer against the canonical
// RFC 5849 HMAC-SHA1 worked example (the widely published api.twitter.com
// statuses/update reference): the same inputs must reproduce the documented
// oauth_signature exactly. A regression in percent-encoding, parameter sorting,
// base-string assembly, or the HMAC key would change this value.
func TestOAuth1AuthHeader_KnownAnswerVector(t *testing.T) {
	t.Parallel()

	u, err := url.Parse("https://api.x.com/1.1/statuses/update.json?include_entities=true")
	require.NoError(t, err)

	body := url.Values{"status": {"Hello Ladies + Gentlemen, a signed OAuth request!"}}
	creds := oauth1Creds{
		consumerKey:    "xvz1evFS4wEEPTGEFPHBog",
		consumerSecret: "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw",
		token:          "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
		tokenSecret:    "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE",
	}

	hdr := oauth1AuthHeader("POST", u, body, creds,
		"kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", 1318622958)

	require.True(t, strings.HasPrefix(hdr, "OAuth "), "header must start with the OAuth scheme")
	require.Contains(t, hdr, `oauth_signature="Ls93hJiZbQ3akF3HF3x1Bz8%2FzU4%3D"`, "signature must match the published reference")
	require.Contains(t, hdr, `oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog"`)
	require.Contains(t, hdr, `oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"`)
	require.Contains(t, hdr, `oauth_signature_method="HMAC-SHA1"`)
	require.Contains(t, hdr, `oauth_timestamp="1318622958"`)
	require.Contains(t, hdr, `oauth_version="1.0"`)
}

func TestPctEncodeOAuth1(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"Ladies Man", "Ladies%20Man"},
		{"abcABC123", "abcABC123"},
		{"-._~", "-._~"},
		{"+/=", "%2B%2F%3D"},
		{"Dogs, Cats & Mice", "Dogs%2C%20Cats%20%26%20Mice"},
		{"☃", "%E2%98%83"}, // multibyte UTF-8 encodes byte-by-byte
	}
	for _, tc := range tests {
		require.Equal(t, tc.want, pctEncodeOAuth1(tc.in), "pctEncodeOAuth1(%q)", tc.in)
	}
}

func TestOAuth1BaseURLStripsDefaultPort(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"https://api.example.com:443/v1/x": "https://api.example.com/v1/x",
		"http://api.example.com:80/v1/x":   "http://api.example.com/v1/x",
		"https://api.example.com:8443/x":   "https://api.example.com:8443/x",
		"https://API.Example.com/x":        "https://api.example.com/x",
	}
	for in, want := range cases {
		u, err := url.Parse(in)
		require.NoError(t, err)
		require.Equal(t, want, oauth1BaseURL(u))
	}
}
