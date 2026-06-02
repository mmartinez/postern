package bitwarden

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseSettings_RecognizedKeys(t *testing.T) {
	t.Parallel()

	s, err := parseSettings(map[string]string{
		"server_url": "https://vault.example.com",
		"bws_path":   "/usr/local/bin/bws",
	})
	require.NoError(t, err)
	require.Equal(t, "https://vault.example.com", s.serverURL)
	require.Equal(t, "/usr/local/bin/bws", s.bwsPath)
}

func TestParseSettings_EmptyMapIsValid(t *testing.T) {
	t.Parallel()

	s, err := parseSettings(nil)
	require.NoError(t, err)
	require.Empty(t, s.serverURL)
	require.Empty(t, s.bwsPath)
}

func TestParseSettings_RejectsUnknownKey(t *testing.T) {
	t.Parallel()

	_, err := parseSettings(map[string]string{"sever_url": "https://typo.example.com"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sever_url")
}

func TestParseSettings_RejectsMalformedServerURL(t *testing.T) {
	t.Parallel()

	for name, raw := range map[string]string{
		"no scheme":    "vault.example.com",
		"bad scheme":   "ftp://vault.example.com",
		"missing host": "https://",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := parseSettings(map[string]string{"server_url": raw})
			require.Error(t, err)
			require.Contains(t, err.Error(), "server_url")
		})
	}
}
