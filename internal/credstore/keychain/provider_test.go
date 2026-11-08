package keychain

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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
	return newProvider(f.open), f
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
	p := newProvider(f.open)

	err := p.Validate(context.Background(), "", nil)
	require.ErrorIs(t, err, ErrNoBackend)
}

func TestProvider_ValidateFailsWhenStoreDoesNotAnswer(t *testing.T) {
	t.Parallel()
	f := &fakeOpener{ring: failingRing{}}
	p := newProvider(f.open)

	require.Error(t, p.Validate(context.Background(), "", nil))
}

func TestProvider_RejectsSettings(t *testing.T) {
	t.Parallel()
	p, _ := newTestProvider()
	settings := map[string]string{"x": "y"}
	require.Error(t, p.Validate(context.Background(), "", settings))
	_, err := p.NewResolver(context.Background(), "", settings)
	require.Error(t, err)
}

// A store whose probe read succeeds (some other tool created the probe key)
// is still a working store.
func TestProvider_ValidateAcceptsAnsweringStore(t *testing.T) {
	t.Parallel()
	p := newProvider((&fakeOpener{ring: &sessionRing{}}).open)
	require.NoError(t, p.Validate(context.Background(), "", nil))
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

// sessionRing models the Secret Service backend, which rewrites its session
// field on every Get: unserialized concurrent reads are a data race.
type sessionRing struct {
	keyringlib.Keyring
	session int
}

func (s *sessionRing) Get(string) (keyringlib.Item, error) {
	s.session++
	return keyringlib.Item{Data: []byte("v")}, nil
}

// Concurrent resolves must be serialized. Run with -race.
func TestResolver_ConcurrentResolve(t *testing.T) {
	t.Parallel()
	ring := &sessionRing{}
	r, err := newProvider((&fakeOpener{ring: ring}).open).NewResolver(context.Background(), "", nil)
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
	require.Equal(t, 8, ring.session)
}

// stall blocks each caller until release is closed, standing in for a store
// waiting on an unlock prompt nobody answers.
type stall struct {
	entered chan struct{} // receives once per call that reaches the store
	release chan struct{}
	calls   atomic.Int32
}

func newStall() *stall {
	return &stall{entered: make(chan struct{}, 8), release: make(chan struct{})}
}

func (s *stall) wait() {
	s.calls.Add(1)
	s.entered <- struct{}{}
	<-s.release
}

// stallingRing stalls every Get.
type stallingRing struct {
	keyringlib.Keyring
	*stall
}

func (r stallingRing) Get(string) (keyringlib.Item, error) {
	r.wait()
	return keyringlib.Item{Data: []byte("v")}, nil
}

// stallingOpen stalls every open, then hands out an empty store.
func stallingOpen(s *stall) func(keyringlib.Config) (keyringlib.Keyring, error) {
	return func(keyringlib.Config) (keyringlib.Keyring, error) {
		s.wait()
		return keyringlib.NewArrayKeyring(nil), nil
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A stalled store read must not outlive the caller's deadline, and while it
// stalls, other reads and health probes must give up at their own deadline
// instead of reaching the store.
func TestResolver_StalledStoreHonorsDeadline(t *testing.T) {
	t.Parallel()
	s := newStall()
	p := newProvider((&fakeOpener{ring: stallingRing{stall: s}}).open)
	r, err := p.NewResolver(context.Background(), "", nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-s.entered; cancel() }()
	_, err = r.Resolve(ctx, "", "keychain://a")
	require.ErrorIs(t, err, context.Canceled)

	_, err = r.Resolve(canceledContext(), "", "keychain://b")
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, p.Validate(canceledContext(), "", nil), context.Canceled)
	require.Equal(t, int32(1), s.calls.Load(), "nothing may reach the store while a read stalls")

	close(s.release)
	got, err := r.Resolve(context.Background(), "", "keychain://c")
	require.NoError(t, err)
	require.Equal(t, "v", got)
}

// The health probe re-runs Validate after every timeout. While the store
// stalls, in its open or its read, repeated probes must give up at their
// deadline without starting another native call.
func TestProvider_StalledProbesDoNotPileUp(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*stall) func(keyringlib.Config) (keyringlib.Keyring, error){
		"open stalls": stallingOpen,
		"read stalls": func(s *stall) func(keyringlib.Config) (keyringlib.Keyring, error) {
			return (&fakeOpener{ring: stallingRing{stall: s}}).open
		},
	}
	for name, opener := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newStall()
			p := newProvider(opener(s))

			ctx, cancel := context.WithCancel(context.Background())
			go func() { <-s.entered; cancel() }()
			require.ErrorIs(t, p.Validate(ctx, "", nil), context.Canceled)

			for range 3 {
				require.ErrorIs(t, p.Validate(canceledContext(), "", nil), context.Canceled)
			}
			require.Equal(t, int32(1), s.calls.Load(), "a probe must not start a native call while one stalls")

			close(s.release)
			require.NoError(t, p.Validate(context.Background(), "", nil))
		})
	}
}

func TestProvider_NewResolverFailsWithoutNativeStore(t *testing.T) {
	t.Parallel()
	f := &fakeOpener{err: keyringlib.ErrNoAvailImpl}
	p := newProvider(f.open)

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
	p := newProvider(f.open)

	require.ErrorIs(t, p.SetSecret(context.Background(), "keychain://anthropic", "v"), ErrNoBackend)
	require.ErrorIs(t, p.RemoveSecret(context.Background(), "keychain://anthropic"), ErrNoBackend)
}

// removeRing reports the native stores' Remove behavior: a missing key is
// ErrKeyNotFound, unlike the in-memory ArrayKeyring.
type removeRing struct {
	keyringlib.Keyring
	err error
}

func (r removeRing) Remove(string) error { return r.err }

func TestProvider_RemoveSecretErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	missing := newProvider((&fakeOpener{ring: removeRing{err: keyringlib.ErrKeyNotFound}}).open)
	require.NoError(t, missing.RemoveSecret(ctx, "keychain://anthropic"), "a missing item must not fail rm")

	broken := newProvider((&fakeOpener{ring: removeRing{err: errors.New("dbus: no reply")}}).open)
	require.ErrorContains(t, broken.RemoveSecret(ctx, "keychain://anthropic"), "dbus: no reply")
}
