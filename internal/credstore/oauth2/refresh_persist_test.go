package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// rotatingIDP is a token endpoint with single-use refresh tokens: every
// refresh_token exchange issues a new access AND refresh token and invalidates
// the previous refresh token (the X / Marktplaats behavior). A stale refresh
// token is rejected with invalid_grant. expires_in is 1s so x/oauth2 treats each
// issued access token as immediately stale and refreshes on the next call.
type rotatingIDP struct {
	srv     *httptest.Server
	mu      sync.Mutex
	current string // the only currently-valid refresh token
	issued  int
}

func newRotatingIDP(t *testing.T, seed string) *rotatingIDP {
	t.Helper()
	idp := &rotatingIDP{current: seed}
	idp.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		idp.mu.Lock()
		defer idp.mu.Unlock()
		if r.PostForm.Get("grant_type") != "refresh_token" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"unsupported_grant_type"}`))
			return
		}
		if r.PostForm.Get("refresh_token") != idp.current {
			// Rotated-away / stale token: single-use semantics reject it.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		idp.issued++
		next := fmt.Sprintf("rt-%d", idp.issued)
		idp.current = next
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("at-%d", idp.issued),
			"refresh_token": next,
			"token_type":    "Bearer",
			"expires_in":    1,
		})
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

func readFileTrimmed(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

// TestRefreshTokenRotationPersistedAndSurvivesRestart is the core of the feature:
// a rotated refresh token is written back to refresh_token_path, and a fresh
// resolver built from the original (now-invalid) seed picks up the persisted
// token instead — proving persistence survives a process restart.
func TestRefreshTokenRotationPersistedAndSurvivesRestart(t *testing.T) {
	t.Parallel()
	const seed = "rt-0"
	idp := newRotatingIDP(t, seed)
	path := filepath.Join(t.TempDir(), "refresh-token")
	p := &Provider{httpClient: idp.srv.Client()}
	settings := rtSettings(idp.srv.URL)
	settings["refresh_token_path"] = path

	res, err := p.NewResolverWithSecondary(context.Background(), "csecret", seed, settings)
	require.NoError(t, err)

	// First exchange rotates rt-0 -> rt-1 and must persist rt-1.
	at, err := res.Resolve(context.Background(), "", "oauth2://mp")
	require.NoError(t, err)
	require.Equal(t, "at-1", at)
	require.Equal(t, "rt-1", readFileTrimmed(t, path), "rotated refresh token must be persisted")

	// Second exchange (token already stale at 1s) rotates rt-1 -> rt-2.
	at, err = res.Resolve(context.Background(), "", "oauth2://mp")
	require.NoError(t, err)
	require.Equal(t, "at-2", at)
	require.Equal(t, "rt-2", readFileTrimmed(t, path))

	// Simulate a restart: a brand-new resolver is constructed from the ORIGINAL
	// seed (as a SealedSecret/env seed would supply), but the persisted file holds
	// rt-2. The server has long invalidated rt-0, so success proves the resolver
	// used the persisted token, not the seed.
	res2, err := p.NewResolverWithSecondary(context.Background(), "csecret", seed, settings)
	require.NoError(t, err)
	at, err = res2.Resolve(context.Background(), "", "oauth2://mp")
	require.NoError(t, err, "post-restart resolver must use the persisted (rotated) refresh token, not the stale seed")
	require.Equal(t, "at-3", at)
	require.Equal(t, "rt-3", readFileTrimmed(t, path))
}

// TestRefreshTokenSeedUsedWhenNoPersistFileYet covers first boot: with the path
// set but no file yet, the configured seed is used and then persisted.
func TestRefreshTokenSeedUsedWhenNoPersistFileYet(t *testing.T) {
	t.Parallel()
	idp := newRotatingIDP(t, "seed-0")
	path := filepath.Join(t.TempDir(), "nested", "refresh-token")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	p := &Provider{httpClient: idp.srv.Client()}
	settings := rtSettings(idp.srv.URL)
	settings["refresh_token_path"] = path

	res, err := p.NewResolverWithSecondary(context.Background(), "csecret", "seed-0", settings)
	require.NoError(t, err)
	_, err = res.Resolve(context.Background(), "", "oauth2://mp")
	require.NoError(t, err)
	require.Equal(t, "rt-1", readFileTrimmed(t, path), "first rotation must seed the persist file")
}

// TestParseSettingsRefreshTokenPath validates the new setting: accepted for the
// refresh grant, rejected for client_credentials, rejected when relative.
func TestParseSettingsRefreshTokenPath(t *testing.T) {
	t.Parallel()
	base := func() map[string]string {
		return map[string]string{"token_url": "https://idp.example.com/token", "client_id": "cid", "grant_type": "refresh_token"}
	}

	t.Run("accepted for refresh grant", func(t *testing.T) {
		t.Parallel()
		m := base()
		m["refresh_token_path"] = "/var/lib/postern/rt"
		s, err := parseSettings(m)
		require.NoError(t, err)
		require.Equal(t, "/var/lib/postern/rt", s.refreshTokenPath)
	})

	t.Run("rejected for client_credentials", func(t *testing.T) {
		t.Parallel()
		m := base()
		m["grant_type"] = "client_credentials"
		m["refresh_token_path"] = "/var/lib/postern/rt"
		_, err := parseSettings(m)
		require.Error(t, err)
	})

	t.Run("rejected when relative", func(t *testing.T) {
		t.Parallel()
		m := base()
		m["refresh_token_path"] = "relative/rt"
		_, err := parseSettings(m)
		require.Error(t, err)
	})

	t.Run("unset leaves persistence disabled", func(t *testing.T) {
		t.Parallel()
		s, err := parseSettings(base())
		require.NoError(t, err)
		require.Empty(t, s.refreshTokenPath)
	})
}
