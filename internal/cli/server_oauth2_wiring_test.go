package cli

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/token"
)

type stubResolver struct{ val string }

func (s stubResolver) Resolve(context.Context, string, string) (string, error) { return s.val, nil }

// plainProvider implements credstore.Provider but NOT SecondarySecretProvider.
type plainProvider struct{ scheme string }

func (p *plainProvider) Name() string                             { return "plain-" + p.scheme }
func (p *plainProvider) Scheme() string                           { return p.scheme }
func (p *plainProvider) ShouldCache(string) bool                  { return true }
func (p *plainProvider) ValidateSettings(map[string]string) error { return nil }
func (p *plainProvider) Validate(context.Context, string, map[string]string) error {
	return nil
}

func (p *plainProvider) NewResolver(_ context.Context, token string, _ map[string]string) (broker.Resolver, error) {
	return stubResolver{val: token}, nil
}

// dualProvider implements credstore.SecondarySecretProvider and records which
// path the wiring drove it down.
type dualProvider struct {
	scheme        string
	gotToken      string
	gotSecondary  string
	usedSecondary bool
}

func (p *dualProvider) Name() string                             { return "dual-" + p.scheme }
func (p *dualProvider) Scheme() string                           { return p.scheme }
func (p *dualProvider) ShouldCache(string) bool                  { return false }
func (p *dualProvider) ValidateSettings(map[string]string) error { return nil }

func (p *dualProvider) Validate(_ context.Context, token string, _ map[string]string) error {
	p.gotToken = token
	return nil
}

func (p *dualProvider) NewResolver(_ context.Context, token string, _ map[string]string) (broker.Resolver, error) {
	return stubResolver{val: token}, nil
}

func (p *dualProvider) ValidateWithSecondary(_ context.Context, token, secondary string, _ map[string]string) error {
	p.gotToken, p.gotSecondary, p.usedSecondary = token, secondary, true
	return nil
}

func (p *dualProvider) NewResolverWithSecondary(_ context.Context, token, secondary string, _ map[string]string) (broker.Resolver, error) {
	p.usedSecondary = true
	return stubResolver{val: token + ":" + secondary}, nil
}

func seededStore(t *testing.T) token.Store {
	t.Helper()
	store := token.NewMemoryStore()
	require.NoError(t, store.Set(context.Background(), "primary", "client-secret-val"))
	require.NoError(t, store.Set(context.Background(), "secondary", "refresh-tok-val"))
	return store
}

func keychainToken(account string) config.Token {
	return config.Token{Source: config.TokenSourceKeychain, KeychainAccount: account}
}

func TestBuildCredStoreResolvers_RefreshTokenRoutesToSecondary(t *testing.T) {
	t.Parallel()
	reg := credstore.NewRegistry()
	dp := &dualProvider{scheme: "oauth2"}
	reg.Register(dp)

	stores := []config.CredStore{{
		Name:         "li",
		Provider:     dp.Name(),
		Token:        keychainToken("primary"),
		RefreshToken: keychainToken("secondary"),
	}}

	resolvers, err := buildCredStoreResolvers(context.Background(), reg, stores, seededStore(t), discardLogger())
	require.NoError(t, err)
	require.True(t, dp.usedSecondary, "a refresh_token block must drive the secondary path")
	require.Equal(t, "client-secret-val", dp.gotToken)
	require.Equal(t, "refresh-tok-val", dp.gotSecondary)

	got, err := resolvers["oauth2"].Resolve(context.Background(), "", "oauth2://li")
	require.NoError(t, err)
	require.Equal(t, "client-secret-val:refresh-tok-val", got)
}

func TestBuildCredStoreResolvers_NoRefreshUsesPrimaryPath(t *testing.T) {
	t.Parallel()
	reg := credstore.NewRegistry()
	dp := &dualProvider{scheme: "oauth2"}
	reg.Register(dp)

	stores := []config.CredStore{{
		Name:     "corp",
		Provider: dp.Name(),
		Token:    keychainToken("primary"),
	}}

	resolvers, err := buildCredStoreResolvers(context.Background(), reg, stores, seededStore(t), discardLogger())
	require.NoError(t, err)
	require.False(t, dp.usedSecondary, "no refresh_token block must use the single-secret path")

	got, err := resolvers["oauth2"].Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)
	require.Equal(t, "client-secret-val", got)
}

func TestBuildCredStoreResolvers_RefreshBlockOnNonSecondaryProviderErrors(t *testing.T) {
	t.Parallel()
	reg := credstore.NewRegistry()
	pp := &plainProvider{scheme: "op"}
	reg.Register(pp)

	stores := []config.CredStore{{
		Name:         "vault",
		Provider:     pp.Name(),
		Token:        keychainToken("primary"),
		RefreshToken: keychainToken("secondary"),
	}}

	_, err := buildCredStoreResolvers(context.Background(), reg, stores, seededStore(t), discardLogger())
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not accept a refresh_token block")
}
