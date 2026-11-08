package keychain

import (
	"context"
	"errors"
	"sync"
	"testing"

	keyringlib "github.com/99designs/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/credstore"
)

// fakeOpener hands out one in-memory keyring and records the config every
// open call used.
type fakeOpener struct {
	ring keyringlib.Keyring
	err  error

	mu   sync.Mutex
	cfgs []keyringlib.Config
}

func (f *fakeOpener) open(cfg keyringlib.Config) (keyringlib.Keyring, error) {
	f.mu.Lock()
	f.cfgs = append(f.cfgs, cfg)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.ring, nil
}

// failingRing is a keyring whose every call fails, standing in for a store
// whose daemon is registered but not answering.
type failingRing struct{ keyringlib.Keyring }

func (failingRing) Get(string) (keyringlib.Item, error) {
	return keyringlib.Item{}, errors.New("dbus: no reply")
}

func newTestProvider(items ...keyringlib.Item) (*Provider, *fakeOpener) {
	f := &fakeOpener{ring: keyringlib.NewArrayKeyring(items)}
	return &Provider{open: f.open}, f
}

func TestProvider_NameAndScheme(t *testing.T) {
	t.Parallel()
	p := NewProvider()
	require.Equal(t, "keychain", p.Name())
	require.Equal(t, "keychain", p.Scheme())
	require.True(t, p.ShouldCache("keychain://anthropic"))
}

func TestProvider_SelfRegisters(t *testing.T) {
	t.Parallel()
	p, ok := credstore.Default().ForScheme("keychain")
	require.True(t, ok)
	require.Equal(t, "keychain", p.Name())
	_, tokenless := p.(credstore.TokenlessProvider)
	require.True(t, tokenless, "a keychain credstore must boot without a token block")
}

func TestProvider_ValidateSettings(t *testing.T) {
	t.Parallel()
	p := NewProvider()
	require.NoError(t, p.ValidateSettings(nil))
	require.NoError(t, p.ValidateSettings(map[string]string{}))
	require.Error(t, p.ValidateSettings(map[string]string{"collection": "login"}))
}

// The library's fallbacks (file, pass, keyctl) are not OS secret stores: the
// file backend would write secrets to disk under a prompted password. Only
// the native stores may be opened.
func TestProvider_OpensOnlyNativeStores(t *testing.T) {
	t.Parallel()
	p, f := newTestProvider()
	require.NoError(t, p.Validate(context.Background(), "", nil))

	require.Len(t, f.cfgs, 1)
	cfg := f.cfgs[0]
	require.ElementsMatch(t, []keyringlib.BackendType{
		keyringlib.KeychainBackend,
		keyringlib.SecretServiceBackend,
	}, cfg.AllowedBackends)
	// The login collection unlocks with the desktop session; a dedicated
	// collection would stay locked behind its own password.
	require.Equal(t, "login", cfg.LibSecretCollectionName)
	// Without this the macOS Keychain prompts on every read by the server.
	require.True(t, cfg.KeychainTrustApplication)
}

func TestProvider_ValidateFailsWithoutNativeStore(t *testing.T) {
	t.Parallel()
	f := &fakeOpener{err: keyringlib.ErrNoAvailImpl}
	p := &Provider{open: f.open}

	err := p.Validate(context.Background(), "", nil)
	require.ErrorIs(t, err, ErrNoBackend)
}

func TestProvider_ValidateFailsWhenStoreDoesNotAnswer(t *testing.T) {
	t.Parallel()
	f := &fakeOpener{ring: failingRing{}}
	p := &Provider{open: f.open}

	require.Error(t, p.Validate(context.Background(), "", nil))
}

func TestProvider_ValidateRejectsSettings(t *testing.T) {
	t.Parallel()
	p, _ := newTestProvider()
	require.Error(t, p.Validate(context.Background(), "", map[string]string{"x": "y"}))
}

func TestResolver_Resolve(t *testing.T) {
	t.Parallel()
	p, _ := newTestProvider(
		keyringlib.Item{Key: "postern/anthropic", Data: []byte("sk-test-value")},
		keyringlib.Item{Key: "postern/empty", Data: nil},
		keyringlib.Item{Key: "other", Data: []byte("not-ours")},
	)
	r, err := p.NewResolver(context.Background(), "", nil)
	require.NoError(t, err)

	cases := []struct {
		name    string
		vaultID string
		ref     string
		want    string
		wantErr string
	}{
		{name: "hit", ref: "keychain://anthropic", want: "sk-test-value"},
		{name: "qualified hit", ref: "keychain+personal://anthropic", want: "sk-test-value"},
		{name: "missing item", ref: "keychain://openai", wantErr: `keychain item "openai" not found`},
		{name: "empty item", ref: "keychain://empty", wantErr: `keychain item "empty" is empty`},
		{name: "unprefixed key is not reachable", ref: "keychain://other", wantErr: "not found"},
		{name: "wrong scheme", ref: "op://vault/item/field", wantErr: "keychain://<item>"},
		{name: "no item name", ref: "keychain://", wantErr: "keychain://<item>"},
		{name: "vault id", vaultID: "v1", ref: "keychain://anthropic", wantErr: "vaultID-scoped resolution is not implemented"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := r.Resolve(context.Background(), tc.vaultID, tc.ref)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// The secret-service backend mutates its session on every Get, so concurrent
// resolves must be serialized. Run with -race.
func TestResolver_ConcurrentResolve(t *testing.T) {
	t.Parallel()
	p, _ := newTestProvider(keyringlib.Item{Key: "postern/a", Data: []byte("v")})
	r, err := p.NewResolver(context.Background(), "", nil)
	require.NoError(t, err)

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, err := r.Resolve(context.Background(), "", "keychain://a")
			assert.NoError(t, err)
			assert.Equal(t, "v", got)
		})
	}
	wg.Wait()
}

func TestProvider_NewResolverFailsWithoutNativeStore(t *testing.T) {
	t.Parallel()
	f := &fakeOpener{err: keyringlib.ErrNoAvailImpl}
	p := &Provider{open: f.open}

	_, err := p.NewResolver(context.Background(), "", nil)
	require.ErrorIs(t, err, ErrNoBackend)
}

func TestProvider_SetAndRemoveSecret(t *testing.T) {
	t.Parallel()
	p, f := newTestProvider()
	ctx := context.Background()

	require.NoError(t, p.SetSecret(ctx, "keychain://anthropic", "sk-test-value"))
	item, err := f.ring.Get("postern/anthropic")
	require.NoError(t, err)
	require.Equal(t, "sk-test-value", string(item.Data))
	require.Equal(t, "postern: anthropic", item.Label)

	r, err := p.NewResolver(ctx, "", nil)
	require.NoError(t, err)
	got, err := r.Resolve(ctx, "", "keychain+personal://anthropic")
	require.NoError(t, err)
	require.Equal(t, "sk-test-value", got)

	require.NoError(t, p.RemoveSecret(ctx, "keychain://anthropic"))
	_, err = f.ring.Get("postern/anthropic")
	require.ErrorIs(t, err, keyringlib.ErrKeyNotFound)
	require.NoError(t, p.RemoveSecret(ctx, "keychain://anthropic"), "rm must be idempotent")
}

func TestProvider_SetSecretRejectsBadInput(t *testing.T) {
	t.Parallel()
	p, _ := newTestProvider()
	ctx := context.Background()

	require.ErrorContains(t, p.SetSecret(ctx, "op://vault/item/field", "v"), "keychain://<item>")
	require.ErrorContains(t, p.SetSecret(ctx, "keychain://", "v"), "keychain://<item>")
	require.ErrorContains(t, p.SetSecret(ctx, "keychain://anthropic", ""), "empty")
	require.ErrorContains(t, p.RemoveSecret(ctx, "bw://uuid"), "keychain://<item>")
}

func TestProvider_SetSecretFailsWithoutNativeStore(t *testing.T) {
	t.Parallel()
	f := &fakeOpener{err: keyringlib.ErrNoAvailImpl}
	p := &Provider{open: f.open}

	require.ErrorIs(t, p.SetSecret(context.Background(), "keychain://anthropic", "v"), ErrNoBackend)
	require.ErrorIs(t, p.RemoveSecret(context.Background(), "keychain://anthropic"), ErrNoBackend)
}
