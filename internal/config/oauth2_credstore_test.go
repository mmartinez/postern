package config_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

// oauth2ProxyTail is the proxy + empty rules block appended to the oauth2
// credstore fixtures below so each test body declares only the credstore.
const oauth2ProxyTail = `
proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m
  on_no_match: passthrough
rules: []
`

func TestOAuth2_RefreshGrantRequiresRefreshTokenBlock(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: li
    provider: oauth2
    token:
      source: env
      env_var: LI_CLIENT_SECRET
    settings:
      token_url: https://idp.example.com/token
      client_id: cid
      grant_type: refresh_token
` + oauth2ProxyTail))
	require.NoError(t, err)
	requireLintContains(t, lints, "refresh_token block")
}

func TestOAuth2_RefreshTokenBlockRequiresRefreshGrant(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: li
    provider: oauth2
    token:
      source: env
      env_var: LI_CLIENT_SECRET
    refresh_token:
      source: env
      env_var: LI_REFRESH_TOKEN
    settings:
      token_url: https://idp.example.com/token
      client_id: cid
      grant_type: client_credentials
` + oauth2ProxyTail))
	require.NoError(t, err)
	requireLintContains(t, lints, "grant_type: refresh_token")
}

func TestOAuth2_ValidRefreshConfigLintsClean(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: li
    provider: oauth2
    token:
      source: env
      env_var: LI_CLIENT_SECRET
    refresh_token:
      source: env
      env_var: LI_REFRESH_TOKEN
    settings:
      token_url: https://idp.example.com/token
      client_id: cid
      grant_type: refresh_token
` + oauth2ProxyTail))
	require.NoError(t, err)
	require.Empty(t, lints, "valid refresh config should lint clean; got %v", lints)
}

func TestOAuth2_ValidClientCredentialsLintsClean(t *testing.T) {
	t.Parallel()
	_, lints, err := config.LoadAndValidate(strings.NewReader(`
credstores:
  - name: corp
    provider: oauth2
    token:
      source: env
      env_var: CORP_CLIENT_SECRET
    settings:
      token_url: https://idp.example.com/token
      client_id: cid
      grant_type: client_credentials
` + oauth2ProxyTail))
	require.NoError(t, err)
	require.Empty(t, lints, "valid client_credentials config should lint clean; got %v", lints)
}
