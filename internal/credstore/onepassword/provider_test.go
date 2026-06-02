package onepassword

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/credstore"
)

func TestProvider_NameAndScheme(t *testing.T) {
	t.Parallel()

	p := NewProvider("test-version")
	require.Equal(t, "1password", p.Name())
	require.Equal(t, "op", p.Scheme())
}

func TestProvider_SelfRegisters(t *testing.T) {
	t.Parallel()

	got, ok := credstore.ForScheme("op")
	require.True(t, ok, "init() should register the provider under scheme op")
	require.Equal(t, "1password", got.Name())
}

func TestProvider_ForOpSecretRef(t *testing.T) {
	t.Parallel()

	got, ok := credstore.ForSecretRef("op://Vault/Item/field")
	require.True(t, ok)
	require.Equal(t, "1password", got.Name())
}

// 1Password recognizes no per-credstore settings keys. ValidateSettings is
// the offline, token-free check the `config validate` path calls; it must
// accept an empty/absent settings block and reject any non-empty one so a
// stray `settings:` on an op credstore is a line-numbered error rather than
// a silently ignored field.
func TestProvider_ValidateSettingsRejectsAnyKeys(t *testing.T) {
	t.Parallel()

	p := NewProvider("test-version")
	require.NoError(t, p.ValidateSettings(nil), "absent settings is valid for 1Password")
	require.NoError(t, p.ValidateSettings(map[string]string{}), "empty settings is valid for 1Password")
	require.Error(t, p.ValidateSettings(map[string]string{"server_url": "https://x"}),
		"1Password recognizes no settings keys; a non-empty settings block must be rejected")
}

func TestProvider_ShouldCacheBypassesOTP(t *testing.T) {
	t.Parallel()

	p := NewProvider("test-version")

	cacheable := []string{
		"op://Vault/Item/field",
		"op://Vault/Item/field?attribute=label", // non-OTP attribute is cacheable
	}
	for _, ref := range cacheable {
		require.True(t, p.ShouldCache(ref), "ordinary reference %q must be cacheable", ref)
	}

	// Every OTP/TOTP reference must bypass the cache, regardless of extra or
	// reordered query parameters — a suffix match would miss these.
	oneTime := []string{
		"op://Vault/Item/totp?attribute=otp",
		"op://Vault/Item/totp?attribute=totp",
		"op://Vault/Item/totp?attribute=otp&label=x",
		"op://Vault/Item/totp?label=x&attribute=otp",
	}
	for _, ref := range oneTime {
		require.False(t, p.ShouldCache(ref),
			"one-time password %q changes every 30s and must never be cached", ref)
	}
}
