package bitwarden

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/credstore"
)

func TestProvider_NameAndScheme(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	require.Equal(t, "bitwarden", p.Name())
	require.Equal(t, "bw", p.Scheme())
}

func TestProvider_SelfRegistersUnderSchemeBW(t *testing.T) {
	t.Parallel()

	// The build tag is gone: the provider must register in the default binary
	// so `provider: bitwarden` configs resolve without a special build.
	got, ok := credstore.ForScheme("bw")
	require.True(t, ok, "init() should register the provider under scheme bw in the default build")
	require.Equal(t, "bitwarden", got.Name())
}

func TestProvider_ShouldCacheAlwaysTrue(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	require.True(t, p.ShouldCache("bw://"+testUUID),
		"Secrets Manager has no rotating-ref grammar; every value is cacheable")
}

func TestProvider_ValidateSettings(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	require.NoError(t, p.ValidateSettings(nil))
	require.NoError(t, p.ValidateSettings(map[string]string{"server_url": "https://vault.example.com"}))
	require.Error(t, p.ValidateSettings(map[string]string{"nope": "x"}))
	require.Error(t, p.ValidateSettings(map[string]string{"server_url": "not-a-url"}))
}

func TestProvider_ValidateSucceedsOnZeroExit(t *testing.T) {

	// `bws secret list` returning an empty list (exit 0) is still a valid token.
	script := writeScript(t, `echo "[]"`)
	p := NewProvider()
	require.NoError(t, p.Validate(context.Background(), "tok", map[string]string{"bws_path": script}))
}

func TestProvider_ValidateSelfHostedAddsServerURL(t *testing.T) {

	// A self-hosted server_url must be forwarded to bws; the script asserts the
	// --server-url flag arrives and exits 0 so Validate succeeds.
	script := writeScript(t, `case " $* " in *" --server-url https://vault.example.com "*) exit 0 ;; *) exit 1 ;; esac`)
	p := NewProvider()
	err := p.Validate(context.Background(), "tok", map[string]string{
		"bws_path":   script,
		"server_url": "https://vault.example.com",
	})
	require.NoError(t, err)
}

func TestProvider_ValidateFailsClosedOnNonZeroExit(t *testing.T) {

	script := writeScript(t, `exit 1`)
	p := NewProvider()
	require.Error(t, p.Validate(context.Background(), "bad-token", map[string]string{"bws_path": script}))
}

func TestProvider_ValidateFailsWhenBwsMissing(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	err := p.Validate(context.Background(), "tok", map[string]string{"bws_path": "/nonexistent/bws"})
	require.ErrorIs(t, err, ErrBwsNotFound)
}

func TestProvider_ValidateRejectsBadSettings(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	require.Error(t, p.Validate(context.Background(), "tok", map[string]string{"nope": "x"}))
}

func TestProvider_NewResolverBuildsWorkingResolver(t *testing.T) {

	script := writeScript(t, `echo '{"value":"sk-real"}'`)
	p := NewProvider()
	r, err := p.NewResolver(context.Background(), "tok", map[string]string{"bws_path": script})
	require.NoError(t, err)

	got, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.NoError(t, err)
	require.Equal(t, "sk-real", got)
}

func TestProvider_NewResolverFailsWhenBwsMissing(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	_, err := p.NewResolver(context.Background(), "tok", map[string]string{"bws_path": "/nonexistent/bws"})
	require.ErrorIs(t, err, ErrBwsNotFound)
}

func TestProvider_NewResolverRejectsBadSettings(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	_, err := p.NewResolver(context.Background(), "tok", map[string]string{"nope": "x"})
	require.Error(t, err)
}
