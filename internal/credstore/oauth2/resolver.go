// Package oauth2 implements a credstore.Provider that brokers OAuth2 access
// tokens. A rule's secret_ref of the form "oauth2://<credstore-name>" resolves
// to a freshly minted (or cached) bearer access token, obtained from the
// configured token endpoint via the client_credentials or refresh_token grant.
//
// Token exchange, in-memory caching, and automatic refresh on expiry are
// delegated to golang.org/x/oauth2; this package adapts its TokenSource to the
// broker.Resolver contract and owns the brand-neutral config mapping. The broker
// cache is bypassed for oauth2 refs (Provider.ShouldCache reports false) so the
// access-token lifetime is governed by the token's own expiry, not a global TTL.
package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/mmartinez/postern/internal/broker"
)

const scheme = "oauth2"

// Grant type identifiers accepted in a credstore's settings.grant_type.
const (
	grantClientCredentials = "client_credentials"
	grantRefreshToken      = "refresh_token"
)

// errNotOAuth2Ref is returned when Resolve is handed a ref that is not an
// oauth2:// reference. The scheme router only dispatches oauth2 refs here, so
// this is a defensive guard rather than an expected path. The authority
// (the part after oauth2://) is reserved for future multi-client selection and
// is not interpreted today: one oauth2 credstore maps to one resolver.
var errNotOAuth2Ref = errors.New("oauth2: not an oauth2 secret_ref")

// oauthConfig is the resolved, brand-neutral input for building a token source.
// It is assembled by the Provider from the credstore's token (client secret),
// secondary secret (refresh token), and settings, and consumed by newResolver.
type oauthConfig struct {
	tokenURL     string
	clientID     string
	clientSecret string
	grantType    string
	refreshToken string
	scopes       []string
	authStyle    xoauth2.AuthStyle
	// httpClient governs the token-endpoint calls (timeout, test transport).
	// nil uses http.DefaultClient via x/oauth2.
	httpClient *http.Client
}

// resolver adapts an x/oauth2 TokenSource to broker.Resolver. The TokenSource is
// thread-safe and caches/refreshes the token internally.
type resolver struct {
	ts xoauth2.TokenSource
}

// newResolver builds a resolver whose TokenSource implements cfg.grantType. The
// token source captures a background context carrying cfg.httpClient; x/oauth2's
// TokenSource.Token does not take a context, so per-request cancellation does not
// reach refreshes (the http client's own timeout bounds them).
func newResolver(cfg oauthConfig) (*resolver, error) {
	ctx := context.Background()
	if cfg.httpClient != nil {
		ctx = context.WithValue(ctx, xoauth2.HTTPClient, cfg.httpClient)
	}

	var ts xoauth2.TokenSource
	switch cfg.grantType {
	case grantClientCredentials:
		cc := &clientcredentials.Config{
			ClientID:     cfg.clientID,
			ClientSecret: cfg.clientSecret,
			TokenURL:     cfg.tokenURL,
			Scopes:       cfg.scopes,
			AuthStyle:    cfg.authStyle,
		}
		ts = cc.TokenSource(ctx)
	case grantRefreshToken:
		oc := &xoauth2.Config{
			ClientID:     cfg.clientID,
			ClientSecret: cfg.clientSecret,
			Scopes:       cfg.scopes,
			Endpoint: xoauth2.Endpoint{
				TokenURL:  cfg.tokenURL,
				AuthStyle: cfg.authStyle,
			},
		}
		ts = oc.TokenSource(ctx, &xoauth2.Token{RefreshToken: cfg.refreshToken})
	default:
		return nil, fmt.Errorf("oauth2: unsupported grant_type %q", cfg.grantType)
	}

	return &resolver{ts: ts}, nil
}

// Resolve returns the access token for secretRef. vaultID is unused (single
// client per credstore). It fails closed on a non-oauth2 ref, a token-endpoint
// error (with the response body stripped), or an empty access token.
func (r *resolver) Resolve(_ context.Context, _, secretRef string) (string, error) {
	if !strings.HasPrefix(secretRef, scheme+"://") {
		return "", fmt.Errorf("%w: %q", errNotOAuth2Ref, secretRef)
	}

	tok, err := r.ts.Token()
	if err != nil {
		return "", sanitizeTokenError(err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("oauth2: token endpoint returned an empty access_token")
	}
	return tok.AccessToken, nil
}

// sanitizeTokenError strips the token-endpoint response body from an x/oauth2
// retrieval error before it can reach a log or a 502 surface. The body of a
// failed token exchange can echo request parameters (including the client
// secret), so only the HTTP status is surfaced.
func sanitizeTokenError(err error) error {
	var re *xoauth2.RetrieveError
	if errors.As(err, &re) && re.Response != nil {
		return fmt.Errorf("oauth2: token endpoint returned status %d", re.Response.StatusCode)
	}
	return errors.New("oauth2: token request failed")
}

var _ broker.Resolver = (*resolver)(nil)
