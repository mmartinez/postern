package token_test

import (
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/token"
)

func TestFingerprint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{
			name:  "long service account token shows first4 and last4",
			token: "ops_eyJhbGciOiJFUzI1NiJ9.PAYLOADhere.a3F2",
			want:  "ops_…a3F2",
		},
		{
			name:  "exactly the prefix-suffix threshold is fully masked",
			token: "abcdefgh",
			want:  "********",
		},
		{
			name:  "twelve character token shows endpoints",
			token: "abcd12345xyz", // gitleaks:allow — synthetic test fixture, not a credential
			want:  "abcd…5xyz",
		},
		{
			name:  "short token is fully masked",
			token: "tiny",
			want:  "****",
		},
		{
			name:  "empty token returns empty literal",
			token: "",
			want:  "<empty>",
		},
		{
			name:  "single character is fully masked",
			token: "x",
			want:  "*",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := token.Fingerprint(tc.token)
			if got != tc.want {
				t.Fatalf("Fingerprint(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}

func TestFingerprintNeverLeaksMiddle(t *testing.T) {
	t.Parallel()

	// A credential-shaped token with a recognizable middle that must never
	// appear in the fingerprint. This is the core invariant: the helper
	// exists to make it safe to log a token reference without leaking the
	// secret material.
	secretMiddle := "DO_NOT_LEAK_THIS_PART"
	full := "ops_" + secretMiddle + "a3F2"

	got := token.Fingerprint(full)
	if strings.Contains(got, secretMiddle) {
		t.Fatalf("Fingerprint(%q) = %q, leaked the secret middle %q", full, got, secretMiddle)
	}
}
