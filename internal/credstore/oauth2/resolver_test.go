package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	xoauth2 "golang.org/x/oauth2"

	"github.com/stretchr/testify/require"
)

// fakeIDP is a minimal OAuth2 token endpoint for resolver tests. It records the
// last request's auth header and form, counts calls, and serves a configurable
// token (or a non-2xx body) so tests can assert wire format, caching, refresh,
// and error handling without sleeping or hitting a real IdP.
type fakeIDP struct {
	srv *httptest.Server

	mu       sync.Mutex
	calls    int
	lastAuth string
	lastForm url.Values

	status      int
	accessToken string
	expiresIn   int
	body        string
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	f := &fakeIDP{status: http.StatusOK, accessToken: "tok-1", expiresIn: 3600}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		f.mu.Lock()
		f.calls++
		f.lastAuth = r.Header.Get("Authorization")
		f.lastForm = r.PostForm
		status, token, expires, body := f.status, f.accessToken, f.expiresIn, f.body
		f.mu.Unlock()

		if status != http.StatusOK {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   expires,
		})
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIDP) count() int       { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }
func (f *fakeIDP) form() url.Values { f.mu.Lock(); defer f.mu.Unlock(); return f.lastForm }
func (f *fakeIDP) authHdr() string  { f.mu.Lock(); defer f.mu.Unlock(); return f.lastAuth }

func TestResolveClientCredentialsBasicAuth(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	r, err := newResolver(oauthConfig{
		tokenURL:     idp.srv.URL,
		clientID:     "cid",
		clientSecret: "csecret",
		grantType:    grantClientCredentials,
		authStyle:    xoauth2.AuthStyleInHeader,
		httpClient:   idp.srv.Client(),
	})
	require.NoError(t, err)

	got, err := r.Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)
	require.Equal(t, "tok-1", got)

	require.True(t, strings.HasPrefix(idp.authHdr(), "Basic "), "creds belong in the Authorization header")
	require.Empty(t, idp.form().Get("client_secret"), "secret must not appear in the body for basic auth")
	require.Equal(t, "client_credentials", idp.form().Get("grant_type"))
}

func TestResolveClientCredentialsPostAuth(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	r, err := newResolver(oauthConfig{
		tokenURL:     idp.srv.URL,
		clientID:     "cid",
		clientSecret: "csecret",
		grantType:    grantClientCredentials,
		authStyle:    xoauth2.AuthStyleInParams,
		httpClient:   idp.srv.Client(),
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)

	require.Empty(t, idp.authHdr(), "post style sends creds in the body, not a Basic header")
	require.Equal(t, "cid", idp.form().Get("client_id"))
	require.Equal(t, "csecret", idp.form().Get("client_secret"))
}

func TestResolveRefreshTokenGrant(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	r, err := newResolver(oauthConfig{
		tokenURL:     idp.srv.URL,
		clientID:     "cid",
		clientSecret: "csecret",
		grantType:    grantRefreshToken,
		refreshToken: "rt-123",
		authStyle:    xoauth2.AuthStyleInParams,
		httpClient:   idp.srv.Client(),
	})
	require.NoError(t, err)

	got, err := r.Resolve(context.Background(), "", "oauth2://li")
	require.NoError(t, err)
	require.Equal(t, "tok-1", got)
	require.Equal(t, "refresh_token", idp.form().Get("grant_type"))
	require.Equal(t, "rt-123", idp.form().Get("refresh_token"))
}

func TestResolveScopePassthrough(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	r, err := newResolver(oauthConfig{
		tokenURL:     idp.srv.URL,
		clientID:     "cid",
		clientSecret: "csecret",
		grantType:    grantClientCredentials,
		scopes:       []string{"read", "write"},
		authStyle:    xoauth2.AuthStyleInParams,
		httpClient:   idp.srv.Client(),
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)
	require.Equal(t, "read write", idp.form().Get("scope"))
}

func TestResolveCachesValidToken(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	idp.expiresIn = 3600 // long-lived → cached across calls
	r, err := newResolver(oauthConfig{
		tokenURL: idp.srv.URL, clientID: "cid", clientSecret: "csecret",
		grantType: grantClientCredentials, authStyle: xoauth2.AuthStyleInHeader,
		httpClient: idp.srv.Client(),
	})
	require.NoError(t, err)

	for range 3 {
		_, err = r.Resolve(context.Background(), "", "oauth2://corp")
		require.NoError(t, err)
	}
	require.Equal(t, 1, idp.count(), "valid token must be reused, not re-exchanged")
}

func TestResolveRefreshesExpiredToken(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	idp.expiresIn = 1 // within x/oauth2's expiry delta → stale immediately, no sleep
	r, err := newResolver(oauthConfig{
		tokenURL: idp.srv.URL, clientID: "cid", clientSecret: "csecret",
		grantType: grantClientCredentials, authStyle: xoauth2.AuthStyleInHeader,
		httpClient: idp.srv.Client(),
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), "", "oauth2://corp")
	require.NoError(t, err)
	require.Equal(t, 2, idp.count(), "an effectively-expired token must be re-exchanged")
}

func TestResolveErrorDoesNotLeakResponseBody(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	idp.status = http.StatusBadRequest
	idp.body = `{"error":"invalid_client","leak":"SUPERSECRETXYZ"}`
	r, err := newResolver(oauthConfig{
		tokenURL: idp.srv.URL, clientID: "cid", clientSecret: "csecret",
		grantType: grantClientCredentials, authStyle: xoauth2.AuthStyleInHeader,
		httpClient: idp.srv.Client(),
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "oauth2://corp")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SUPERSECRETXYZ", "token-endpoint response body must never appear in errors")
	require.Contains(t, err.Error(), "400", "status code is safe to surface")
}

func TestResolveRejectsNonOAuth2Ref(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	r, err := newResolver(oauthConfig{
		tokenURL: idp.srv.URL, clientID: "cid", clientSecret: "csecret",
		grantType: grantClientCredentials, authStyle: xoauth2.AuthStyleInHeader,
		httpClient: idp.srv.Client(),
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "op://Vault/Item/field")
	require.ErrorIs(t, err, errNotOAuth2Ref)
	require.Equal(t, 0, idp.count(), "a non-oauth2 ref must not trigger an exchange")
}

func TestResolveRejectsEmptyAccessToken(t *testing.T) {
	t.Parallel()
	idp := newFakeIDP(t)
	idp.accessToken = ""
	r, err := newResolver(oauthConfig{
		tokenURL: idp.srv.URL, clientID: "cid", clientSecret: "csecret",
		grantType: grantClientCredentials, authStyle: xoauth2.AuthStyleInHeader,
		httpClient: idp.srv.Client(),
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "oauth2://corp")
	require.Error(t, err)
}

func TestNewResolverRejectsUnknownGrant(t *testing.T) {
	t.Parallel()
	_, err := newResolver(oauthConfig{
		tokenURL: "https://idp.example.com/token", clientID: "cid",
		grantType: "password",
	})
	require.Error(t, err)
}
