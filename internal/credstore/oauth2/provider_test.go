package oauth2

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/credstore"
)

// providerFor returns a Provider whose token-endpoint calls are routed to idp.
func providerFor(idp *fakeIDP) *Provider {
	return &Provider{httpClient: idp.srv.Client()}
}

func ccSettings(tokenURL string) map[string]string {
	return map[string]string{
		"token_url":  tokenURL,
		"client_id":  "cid",
		"grant_type": "client_credentials",
	}
}

func rtSettings(tokenURL string) map[string]string {
	return map[string]string{
		"token_url":  tokenURL,
		"client_id":  "cid",
		"grant_type": "refresh_token",
	}
}

func TestProviderIdentity(t *testing.T) {
	t.Parallel()
	p := NewProvider()
	require.Equal(t, "oauth2", p.Name())
	require.Equal(t, "oauth2", p.Scheme())
	require.False(t, p.ShouldCache("oauth2://corp"), "oauth2 refs must bypass the broker cache")
}

func TestProviderImplementsSecondarySecret(t *testing.T) {
	t.Parallel()
	var _ credstore.SecondarySecretProvider = NewProvider()
}

func TestValidateSettings(t *testing.T) {
	t.Parallel()
	base := func() map[string]string {
		return map[string]string{
			"token_url":  "https://idp.example.com/token",
			"client_id":  "cid",
			"grant_type": "client_credentials",
		}
	}
	tests := []struct {
		name string
		in   map[string]string
		ok   bool
	}{
		{"client_credentials ok", base(), true},
		{"refresh_token ok", map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid", "grant_type": "refresh_token"}, true},
		{"scope and post auth_style", map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid", "grant_type": "client_credentials", "scope": "a b", "auth_style": "post"}, true},
		{"missing token_url", map[string]string{"client_id": "cid", "grant_type": "client_credentials"}, false},
		{"http token_url", map[string]string{"token_url": "http://idp.example.com/token", "client_id": "cid", "grant_type": "client_credentials"}, false},
		{"relative token_url", map[string]string{"token_url": "/token", "client_id": "cid", "grant_type": "client_credentials"}, false},
		{"missing client_id", map[string]string{"token_url": "https://idp.example.com/token", "grant_type": "client_credentials"}, false},
		{"missing grant_type", map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid"}, false},
		{"bad grant_type", map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid", "grant_type": "password"}, false},
		{"bad auth_style", map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid", "grant_type": "client_credentials", "auth_style": "jwt"}, false},
		{"unknown key", map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid", "grant_type": "client_credentials", "wat": "x"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := NewProvider().ValidateSettings(tc.in)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestValidateBootPingClientCredentials(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	err := providerFor(idp).Validate(context.Background(), "csecret", ccSettings(idp.srv.URL))
	require.NoError(t, err)
	require.Equal(t, 1, idp.count(), "Validate must perform exactly one boot exchange")
}

func TestValidateRejectsRefreshGrantWithoutSecondary(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	err := providerFor(idp).Validate(context.Background(), "csecret", rtSettings(idp.srv.URL))
	require.Error(t, err)
	require.Equal(t, 0, idp.count(), "a refresh grant without a refresh token must not exchange")
}

func TestValidateWithSecondaryRefreshTokenSkipsLiveExchange(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	err := providerFor(idp).ValidateWithSecondary(context.Background(), "csecret", "rt-1", rtSettings(idp.srv.URL))
	require.NoError(t, err)
	require.Equal(t, 0, idp.count(), "the refresh grant validates offline; a live boot exchange would consume/rotate the refresh token")
}

func TestValidateWithSecondaryRejectsClientCredentials(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	err := providerFor(idp).ValidateWithSecondary(context.Background(), "csecret", "rt-1", ccSettings(idp.srv.URL))
	require.Error(t, err, "a refresh token against a client_credentials grant is a misconfig")
}

func TestNewResolverClientCredentials(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	res, err := providerFor(idp).NewResolver(context.Background(), "csecret", ccSettings(idp.srv.URL))
	require.NoError(t, err)
	got, err := res.Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)
	require.Equal(t, "tok-1", got)
}

func TestNewResolverWithSecondaryRefreshToken(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	res, err := providerFor(idp).NewResolverWithSecondary(context.Background(), "csecret", "rt-1", rtSettings(idp.srv.URL))
	require.NoError(t, err)
	got, err := res.Resolve(context.Background(), "", "oauth2://li")
	require.NoError(t, err)
	require.Equal(t, "tok-1", got)
}
