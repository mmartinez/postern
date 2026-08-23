package credstore_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/credstore"
)

func TestParseQualifiedRef(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ref    string
		scheme string
		store  string
		ok     bool
	}{
		{name: "unqualified", ref: "op://Vault/Item/field", scheme: "op", ok: true},
		{name: "qualified", ref: "op+team://Agents/Anthropic/api_key", scheme: "op", store: "team", ok: true},
		{name: "qualified oauth2 keeps authority form parseable", ref: "oauth2://corp", scheme: "oauth2", ok: true},
		{name: "scheme with plus still splits at last plus", ref: "a+b+team://x/y", scheme: "a+b", store: "team", ok: true},
		{name: "missing separator", ref: "op+team", ok: false},
		{name: "empty head", ref: "://x", ok: false},
		{name: "empty qualifier", ref: "op+://Vault/Item", ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scheme, store, ok := credstore.ParseQualifiedRef(tc.ref)
			require.Equal(t, tc.ok, ok, "ok for %q", tc.ref)
			require.Equal(t, tc.scheme, scheme, "scheme for %q", tc.ref)
			require.Equal(t, tc.store, store, "credstore name for %q", tc.ref)
		})
	}
}

func TestStripQualifier(t *testing.T) {
	t.Parallel()

	require.Equal(t, "op://Vault/Item/field", credstore.StripQualifier("op+team://Vault/Item/field"))
	require.Equal(t, "op://Vault/Item/field", credstore.StripQualifier("op://Vault/Item/field"))
	require.Equal(t, "not-a-uri", credstore.StripQualifier("not-a-uri"))
}
