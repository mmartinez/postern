package credstore_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"

	// Side-effect import so the canonical provider self-registers into
	// the default registry before TestDefaultPackageFuncs runs. Without
	// this, the registry is empty during credstore-package-only tests.
	_ "github.com/mmartinez/postern/internal/credstore/onepassword"
)

type fakeProvider struct {
	name, scheme string
}

func (f *fakeProvider) Name() string                               { return f.name }
func (f *fakeProvider) Scheme() string                             { return f.scheme }
func (f *fakeProvider) ShouldCache(_ string) bool                  { return true }
func (f *fakeProvider) ValidateSettings(_ map[string]string) error { return nil }
func (f *fakeProvider) Validate(_ context.Context, _ string, _ map[string]string) error {
	return nil
}

func (f *fakeProvider) NewResolver(_ context.Context, _ string, _ map[string]string) (broker.Resolver, error) {
	return nil, nil
}

func TestRegistry_RegisterAndForScheme(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	op := &fakeProvider{name: "op", scheme: "op"}
	r.Register(op)

	got, ok := r.ForScheme("op")
	require.True(t, ok)
	require.Same(t, op, got)
}

func TestRegistry_ForSecretRef(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	op := &fakeProvider{name: "op", scheme: "op"}
	bw := &fakeProvider{name: "bw", scheme: "bw"}
	r.Register(op)
	r.Register(bw)

	tests := map[string]credstore.Provider{
		"op://Vault/Item/field":      op,
		"bw://collection/item/field": bw,
	}
	for ref, want := range tests {
		got, ok := r.ForSecretRef(ref)
		require.Truef(t, ok, "expected provider for %q", ref)
		require.Samef(t, want, got, "wrong provider for %q", ref)
	}
}

func TestRegistry_ForSecretRefUnknown(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	r.Register(&fakeProvider{name: "op", scheme: "op"})

	_, ok := r.ForSecretRef("vault://x/y")
	require.False(t, ok)
}

func TestRegistry_RegisterDuplicatePanics(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	r.Register(&fakeProvider{name: "op", scheme: "op"})

	require.Panics(t, func() {
		r.Register(&fakeProvider{name: "op-dup", scheme: "op"})
	})
}

func TestRegistry_RegisterNilPanics(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	require.Panics(t, func() { r.Register(nil) })
}

func TestRegistry_RegisterEmptySchemePanics(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	require.Panics(t, func() {
		r.Register(&fakeProvider{name: "noscheme", scheme: ""})
	})
}

func TestRegistry_RegisterEmptyNamePanics(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	require.Panics(t, func() {
		r.Register(&fakeProvider{name: "", scheme: "x"})
	})
}

func TestRegistry_RegisterDuplicateNamePanics(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	r.Register(&fakeProvider{name: "same", scheme: "a"})
	require.Panics(t, func() {
		r.Register(&fakeProvider{name: "same", scheme: "b"})
	})
}

func TestRegistry_ForName(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	want := &fakeProvider{name: "op", scheme: "op"}
	r.Register(want)

	got, ok := r.ForName("op")
	require.True(t, ok)
	require.Same(t, want, got)

	_, ok = r.ForName("missing")
	require.False(t, ok)
}

func TestRegistry_Providers(t *testing.T) {
	t.Parallel()

	r := credstore.NewRegistry()
	r.Register(&fakeProvider{name: "a", scheme: "a"})
	r.Register(&fakeProvider{name: "b", scheme: "b"})

	got := r.Providers()
	require.Len(t, got, 2)
}

// TestDefaultPackageFuncs covers the package-level wrappers that
// delegate to the process-wide default Registry. The canonical credstore
// provider has already self-registered via init() before this test runs,
// so the assertions below probe the wrappers without mutating shared
// state. The provider's name string is intentionally not hard-coded here
// to keep the credstore package brand-agnostic.
func TestDefaultPackageFuncs(t *testing.T) {
	t.Parallel()

	got, ok := credstore.ForScheme("op")
	require.True(t, ok, "canonical credstore provider should be registered in the default registry")
	require.NotEmpty(t, got.Name())

	got2, ok := credstore.ForName(got.Name())
	require.True(t, ok)
	require.Same(t, got, got2)

	got3, ok := credstore.ForSecretRef("op://Vault/Item/field")
	require.True(t, ok)
	require.Same(t, got, got3)

	require.NotEmpty(t, credstore.Providers())
}
