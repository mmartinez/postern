package oauth2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	xoauth2 "golang.org/x/oauth2"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"
)

const providerName = "oauth2"

// defaultTokenTimeout bounds a token-endpoint call when the Provider has no
// injected HTTP client (the production path).
const defaultTokenTimeout = 30 * time.Second

// Provider implements credstore.Provider (and credstore.SecondarySecretProvider)
// for OAuth2. It is a stateless process-wide singleton: the client secret arrives
// as the primary token, the refresh token as the secondary, and the token
// endpoint config in settings, all consumed transiently per call.
type Provider struct {
	// httpClient overrides the token-endpoint HTTP client. nil uses a client
	// with defaultTokenTimeout. Set in tests to target an httptest IdP.
	httpClient *http.Client
}

// NewProvider constructs a Provider.
func NewProvider() *Provider { return &Provider{} }

// Name returns the registry-facing provider name.
func (p *Provider) Name() string { return providerName }

// Scheme returns the secret-reference URI scheme oauth2 refs use.
func (p *Provider) Scheme() string { return scheme }

// ShouldCache always reports false: an OAuth2 access token is short-lived and
// its lifetime is governed by the token's own expiry, which x/oauth2 honors
// inside the resolver. Caching it under the broker's global TTL would risk
// serving an expired token, so oauth2 refs bypass the broker cache entirely.
func (p *Provider) ShouldCache(string) bool { return false }

// ValidateSettings checks the token-endpoint settings offline (no token, no
// network), so a typo is a line-numbered `config validate` error rather than a
// boot failure.
func (p *Provider) ValidateSettings(settings map[string]string) error {
	_, err := parseSettings(settings)
	return err
}

// Validate performs a boot-time token exchange with the client_credentials
// grant to prove the credentials are live, failing the proxy closed at boot
// rather than at the first request. A refresh_token grant has no client-only
// validation and must use ValidateWithSecondary.
func (p *Provider) Validate(ctx context.Context, token string, settings map[string]string) error {
	return p.validate(ctx, token, "", settings)
}

// ValidateWithSecondary performs a boot-time refresh exchange using token (the
// client secret) and secondary (the refresh token).
func (p *Provider) ValidateWithSecondary(ctx context.Context, token, secondary string, settings map[string]string) error {
	return p.validate(ctx, token, secondary, settings)
}

// NewResolver returns a broker.Resolver for the client_credentials grant.
func (p *Provider) NewResolver(_ context.Context, token string, settings map[string]string) (broker.Resolver, error) {
	return p.buildResolver(token, "", settings)
}

// NewResolverWithSecondary returns a broker.Resolver for the refresh_token grant.
func (p *Provider) NewResolverWithSecondary(_ context.Context, token, secondary string, settings map[string]string) (broker.Resolver, error) {
	return p.buildResolver(token, secondary, settings)
}

// validate builds a resolver and forces one token exchange to confirm the
// credentials work. The probe ref is synthetic; the resolver does not interpret
// the authority.
func (p *Provider) validate(ctx context.Context, clientSecret, refreshToken string, settings map[string]string) error {
	res, err := p.buildResolver(clientSecret, refreshToken, settings)
	if err != nil {
		return err
	}
	if _, err := res.Resolve(ctx, "", scheme+"://_validate"); err != nil {
		return fmt.Errorf("oauth2 validate: %w", err)
	}
	return nil
}

// buildResolver maps settings + secrets to an oauthConfig and constructs the
// resolver. It enforces that the refresh-token secret matches the grant: the
// refresh_token grant requires it, client_credentials forbids it.
func (p *Provider) buildResolver(clientSecret, refreshToken string, settings map[string]string) (*resolver, error) {
	s, err := parseSettings(settings)
	if err != nil {
		return nil, err
	}
	switch s.grantType {
	case grantClientCredentials:
		if refreshToken != "" {
			return nil, errors.New("oauth2: grant_type client_credentials does not take a refresh_token block")
		}
	case grantRefreshToken:
		if refreshToken == "" {
			return nil, errors.New("oauth2: grant_type refresh_token requires a refresh_token block")
		}
	}

	client := p.httpClient
	if client == nil {
		client = &http.Client{
			Timeout: defaultTokenTimeout,
			// An RFC 6749 token endpoint never legitimately redirects. Refusing
			// to follow redirects keeps the client secret from being re-sent to a
			// redirect target (e.g. a DNS-rebound internal/cleartext address).
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return newResolver(oauthConfig{
		tokenURL:     s.tokenURL,
		clientID:     s.clientID,
		clientSecret: clientSecret,
		grantType:    s.grantType,
		refreshToken: refreshToken,
		scopes:       s.scopes,
		authStyle:    s.authStyle,
		httpClient:   client,
	})
}

// settings is the parsed, validated token-endpoint configuration.
type settings struct {
	tokenURL  string
	clientID  string
	grantType string
	scopes    []string
	authStyle xoauth2.AuthStyle
}

// knownSettingKeys is the closed set of recognized settings keys; any other key
// is a config error so a typo never silently no-ops.
var knownSettingKeys = map[string]bool{
	"token_url":  true,
	"client_id":  true,
	"grant_type": true,
	"scope":      true,
	"auth_style": true,
}

// parseSettings validates and parses the provider settings map. grant_type is
// required and explicit (never inferred); token_url must be an absolute https
// URL; auth_style defaults to basic (HTTP Basic).
func parseSettings(m map[string]string) (settings, error) {
	var s settings
	for k := range m {
		if !knownSettingKeys[k] {
			return s, fmt.Errorf("oauth2: unknown setting %q", k)
		}
	}

	s.tokenURL = m["token_url"]
	if s.tokenURL == "" {
		return s, errors.New("oauth2: token_url is required")
	}
	u, err := url.Parse(s.tokenURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return s, fmt.Errorf("oauth2: token_url must be an absolute https URL: %q", s.tokenURL)
	}

	s.clientID = m["client_id"]
	if s.clientID == "" {
		return s, errors.New("oauth2: client_id is required")
	}

	switch m["grant_type"] {
	case grantClientCredentials, grantRefreshToken:
		s.grantType = m["grant_type"]
	case "":
		return s, errors.New("oauth2: grant_type is required (client_credentials or refresh_token)")
	default:
		return s, fmt.Errorf("oauth2: unsupported grant_type %q", m["grant_type"])
	}

	switch m["auth_style"] {
	case "", "basic":
		s.authStyle = xoauth2.AuthStyleInHeader
	case "post":
		s.authStyle = xoauth2.AuthStyleInParams
	default:
		return s, fmt.Errorf("oauth2: unsupported auth_style %q (basic or post)", m["auth_style"])
	}

	if sc := strings.TrimSpace(m["scope"]); sc != "" {
		s.scopes = strings.Fields(sc)
	}
	return s, nil
}

// init wires this provider into the process-wide credstore registry via the
// side-effect-import pattern (mirrors database/sql/driver).
func init() {
	credstore.Register(NewProvider())
}

var _ credstore.SecondarySecretProvider = (*Provider)(nil)
