package identity_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/identity"
)

func TestEnrollment(t *testing.T) {
	t.Parallel()
	key, verifier, err := identity.Generate()
	require.NoError(t, err)
	require.True(t, len(key) == 47, "incorrect key length")
	require.Equal(t, "pst_", key[:4])
	raw, err := base64.RawURLEncoding.DecodeString(key[4:])
	require.NoError(t, err)
	require.True(t, len(raw) == 32, "incorrect entropy length")
	digest := sha256.Sum256([]byte(key))
	require.True(t, hex.EncodeToString(digest[:]) == verifier, "incorrect verifier")
	other, _, err := identity.Generate()
	require.NoError(t, err)
	require.True(t, key != other)
}

func TestVerifierValidation(t *testing.T) {
	t.Parallel()
	_, verifier, err := identity.Generate()
	require.NoError(t, err)
	for _, name := range []string{"a", "Agent_1", "agent-name"} {
		_, err := identity.NewVerifier(name, verifier)
		require.NoError(t, err)
	}
	for _, name := range []string{"", " agent", "a.b", "é", "-a"} {
		_, err := identity.NewVerifier(name, verifier)
		require.Error(t, err)
		require.False(t, strings.Contains(err.Error(), verifier), "verifier appeared in error")
	}
	for _, value := range []string{"", "invalid", verifier[:62]} {
		_, err := identity.NewVerifier("agent", value)
		require.Error(t, err)
	}
}

func TestAuthenticationAndOpaquePrincipal(t *testing.T) {
	t.Parallel()
	key, digest, err := identity.Generate()
	require.NoError(t, err)
	v, err := identity.NewVerifier("agent", digest)
	require.NoError(t, err)
	p := identity.NewPrincipal("agent")
	require.Equal(t, "agent", p.Name())
	require.True(t, v.Authenticate("agent", key))
	require.False(t, v.Authenticate("other", key))
	require.False(t, v.Authenticate("agent", "invalid"))
	require.False(t, (identity.Verifier{}).Authenticate("agent", key))
	ctx := identity.WithPrincipal(context.Background(), p)
	require.Same(t, p, identity.FromContext(ctx))
	require.Nil(t, identity.FromContext(context.Background()))
	require.False(t, strings.Contains(fmt.Sprint(p), digest), "principal exposed verifier")
	require.False(t, strings.Contains(fmt.Sprint(v), digest), "verifier exposed digest")
	select {
	case <-p.Done():
		t.Fatal("new principal revoked")
	default:
	}
	p.Revoke()
	p.Revoke()
	select {
	case <-p.Done():
	default:
		t.Fatal("revocation not published")
	}
	require.NotSame(t, p, identity.NewPrincipal("agent"))
}
