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
	"os"
	"path/filepath"
	"strings"
	"sync"

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
	// refreshTokenPath, when non-empty, is a writable file where a rotated
	// refresh token is persisted so it survives a process restart. Empty
	// disables persistence (the in-memory-only legacy behavior).
	refreshTokenPath string
	// httpClient governs the token-endpoint calls (timeout, test transport).
	// nil uses http.DefaultClient via x/oauth2.
	httpClient *http.Client
}

// resolver adapts an x/oauth2 TokenSource to broker.Resolver. The TokenSource is
// thread-safe and caches/refreshes the token internally.
//
// When persistPath is set (refresh_token grant only), the resolver watches each
// minted token for a rotated refresh token and writes the new value back to
// persistPath atomically. Servers that issue single-use refresh tokens (X,
// Marktplaats, …) invalidate the previous refresh token on every refresh; without
// persistence the rotated token lives only in the TokenSource's memory and is lost
// on restart, leaving the on-disk seed permanently invalid. mu guards lastRefresh
// and the write so concurrent Resolve calls persist at most once per rotation.
type resolver struct {
	ts xoauth2.TokenSource

	persistPath string
	mu          sync.Mutex
	lastRefresh string
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

	// lastRefresh seeds the rotation watermark with the refresh token the
	// TokenSource starts from, so only a genuine rotation triggers a write.
	return &resolver{ts: ts, persistPath: cfg.refreshTokenPath, lastRefresh: cfg.refreshToken}, nil
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
	if err := r.persistRotatedRefreshToken(tok.RefreshToken); err != nil {
		// Fail closed: the server has already invalidated the previous refresh
		// token, so a token we cannot record will brick the next restart. Surface
		// it now (502) rather than silently degrade. The access token returned by
		// this same exchange stays valid in the TokenSource cache, so a transient
		// write error recovers on the next attempt once the path is writable.
		return "", err
	}
	return tok.AccessToken, nil
}

// persistRotatedRefreshToken writes refreshToken back to persistPath when it has
// rotated since the last persisted value. It is a no-op when persistence is
// disabled (persistPath empty), the server did not return a refresh token, or the
// value is unchanged — so a cached (non-refreshing) Token() call writes nothing.
func (r *resolver) persistRotatedRefreshToken(refreshToken string) error {
	if r.persistPath == "" || refreshToken == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if refreshToken == r.lastRefresh {
		return nil
	}
	if err := writeRefreshTokenFile(r.persistPath, refreshToken); err != nil {
		return fmt.Errorf("oauth2: persist rotated refresh token: %w", err)
	}
	r.lastRefresh = refreshToken
	return nil
}

// writeRefreshTokenFile atomically replaces path with token (no trailing
// newline; readers trim). It writes a sibling temp file at 0600 and renames it
// over path, so a crash mid-write never leaves a truncated refresh token that
// would brick the next restart. The temp file shares path's directory so the
// rename is a same-filesystem atomic operation.
func writeRefreshTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".refresh-token-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.WriteString(token); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// readPersistedRefreshToken returns the trimmed contents of a previously
// persisted refresh-token file. A missing file returns "" with no error (first
// boot, before any rotation) so the caller falls back to the configured seed;
// any other read error is surfaced so a non-writable/unreadable mount fails the
// resolver build loudly rather than silently dropping persistence.
func readPersistedRefreshToken(path string) (string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-supplied refresh-token path is intentional
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("oauth2: read persisted refresh token: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
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
	// A non-RetrieveError is a transport/setup failure (DNS, dial, TLS, timeout)
	// with no token-endpoint response body, so its context is safe to preserve.
	return fmt.Errorf("oauth2: token request failed: %w", err)
}

var _ broker.Resolver = (*resolver)(nil)
