package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/token"
)

// tokenlessProvider is a credstore.TokenlessProvider: it authenticates with no
// service-account token.
type tokenlessProvider struct{ plainProvider }

func (*tokenlessProvider) Tokenless() {}

func TestBuildCredStoreResolvers_TokenlessProviderBootsWithoutToken(t *testing.T) {
	t.Parallel()
	reg := credstore.NewRegistry()
	reg.Register(&tokenlessProvider{plainProvider{scheme: "keychain"}})

	// An empty token store: any attempt to resolve a token would fail.
	stores := []config.CredStore{{Name: "desktop", Provider: "plain-keychain"}}
	resolvers, err := buildCredStoreResolvers(context.Background(), reg, stores, token.NewMemoryStore(), discardLogger(), nil)
	require.NoError(t, err)
	require.Contains(t, resolvers, "desktop")
}

func TestBuildCredStoreResolvers_TokenlessProviderRejectsTokenBlock(t *testing.T) {
	t.Parallel()
	reg := credstore.NewRegistry()
	reg.Register(&tokenlessProvider{plainProvider{scheme: "keychain"}})

	stores := []config.CredStore{{Name: "desktop", Provider: "plain-keychain", Token: keychainToken("primary")}}
	_, err := buildCredStoreResolvers(context.Background(), reg, stores, seededStore(t), discardLogger(), nil)
	require.ErrorContains(t, err, `credstore "desktop": provider "plain-keychain" takes no token block`)
}

func TestBuildCredStoreResolvers_TokenProviderStillNeedsToken(t *testing.T) {
	t.Parallel()
	reg := credstore.NewRegistry()
	reg.Register(&plainProvider{scheme: "op"})

	stores := []config.CredStore{{Name: "vault", Provider: "plain-op"}}
	_, err := buildCredStoreResolvers(context.Background(), reg, stores, token.NewMemoryStore(), discardLogger(), nil)
	require.ErrorContains(t, err, "resolve service-account token")
}
