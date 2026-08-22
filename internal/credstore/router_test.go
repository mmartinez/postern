package credstore_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"
)

var errStubMiss = errors.New("stub: no such secret_ref")

// stubResolver answers from a fixed table and records every ref it was
// handed, so tests can assert the router stripped the qualifier before
// delegating.
type stubResolver struct {
	mu     sync.Mutex
	values map[string]string
	seen   []string
}

func (s *stubResolver) Resolve(_ context.Context, _, secretRef string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = append(s.seen, secretRef)
	if v, ok := s.values[secretRef]; ok {
		return v, nil
	}
	return "", errStubMiss
}

func newRouter(t *testing.T, personal, team *stubResolver) *credstore.NameRouter {
	t.Helper()
	r, err := credstore.NewNameRouter(
		map[string]broker.Resolver{"personal": personal, "team": team},
		map[string][]string{"op": {"personal", "team"}},
	)
	require.NoError(t, err)
	return r
}

func TestNameRouter_QualifiedRefRoutesToNamedStore(t *testing.T) {
	t.Parallel()

	personal := &stubResolver{values: map[string]string{"op://Vault/Item/field": "from-personal"}}
	team := &stubResolver{values: map[string]string{
		"op://Vault/Item/field":         "from-team",
		"op://Agents/Anthropic/api_key": "from-team",
	}}
	r := newRouter(t, personal, team)
	ctx := context.Background()

	v, err := r.Resolve(ctx, "", "op+personal://Vault/Item/field")
	require.NoError(t, err)
	require.Equal(t, "from-personal", v)

	v, err = r.Resolve(ctx, "", "op+team://Agents/Anthropic/api_key")
	require.NoError(t, err)
	require.Equal(t, "from-team", v)

	// The named store must see the plain vendor-shaped ref, never the
	// qualified form, and vaultID stays "" per the Resolver contract.
	require.Equal(t, []string{"op://Vault/Item/field"}, personal.seen)
	require.Equal(t, []string{"op://Agents/Anthropic/api_key"}, team.seen)
}

func TestNameRouter_UnqualifiedRefRoutesWhenUnambiguous(t *testing.T) {
	t.Parallel()

	op := &stubResolver{values: map[string]string{"op://V/I/f": "only-store"}}
	bw := &stubResolver{values: map[string]string{}}
	r, err := credstore.NewNameRouter(
		map[string]broker.Resolver{"solo-op": op, "other-vendor": bw},
		map[string][]string{"op": {"solo-op"}, "bw": {"other-vendor"}},
	)
	require.NoError(t, err)

	v, err := r.Resolve(context.Background(), "", "op://V/I/f")
	require.NoError(t, err)
	require.Equal(t, "only-store", v)
}

func TestNameRouter_UnqualifiedAmbiguousSchemeErrors(t *testing.T) {
	t.Parallel()

	r := newRouter(t,
		&stubResolver{values: map[string]string{}},
		&stubResolver{values: map[string]string{"op://Vault/Item/field": "from-team"}},
	)

	_, err := r.Resolve(context.Background(), "", "op://Vault/Item/field")
	require.Error(t, err)
	require.Contains(t, err.Error(), `"personal"`)
	require.Contains(t, err.Error(), `"team"`)
	require.Contains(t, err.Error(), "qualify")

	// A qualified ref against the same two stores still routes.
	v, err := r.Resolve(context.Background(), "", "op+team://Vault/Item/field")
	require.NoError(t, err)
	require.NotEmpty(t, v)
}

func TestNameRouter_UnknownCredstoreNameErrors(t *testing.T) {
	t.Parallel()

	r := newRouter(t,
		&stubResolver{values: map[string]string{}},
		&stubResolver{values: map[string]string{}},
	)

	_, err := r.Resolve(context.Background(), "", "op+ghost://Vault/Item/field")
	require.Error(t, err)
	require.ErrorIs(t, err, credstore.ErrUnknownScheme)
	require.Contains(t, err.Error(), "ghost")
}

func TestNameRouter_UnknownSchemeErrors(t *testing.T) {
	t.Parallel()

	r, err := credstore.NewNameRouter(
		map[string]broker.Resolver{"op-store": &stubResolver{values: map[string]string{}}},
		map[string][]string{"op": {"op-store"}},
	)
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "vault://x/y/z")
	require.Error(t, err)
	require.ErrorIs(t, err, credstore.ErrUnknownScheme)
}

func TestNameRouter_NamesExposesSchemeOwnership(t *testing.T) {
	t.Parallel()

	r := newRouter(t,
		&stubResolver{values: map[string]string{}},
		&stubResolver{values: map[string]string{}},
	)
	require.Equal(t, []string{"personal", "team"}, r.Names("op"))
	require.Empty(t, r.Names("bw"))
}

func TestNameRouter_RejectsBadInput(t *testing.T) {
	t.Parallel()

	resolvers := map[string]broker.Resolver{"a": &stubResolver{values: map[string]string{}}}

	_, err := credstore.NewNameRouter(nil, nil)
	require.Error(t, err)

	_, err = credstore.NewNameRouter(map[string]broker.Resolver{"": resolvers["a"]}, nil)
	require.Error(t, err)

	_, err = credstore.NewNameRouter(map[string]broker.Resolver{"a": nil}, nil)
	require.Error(t, err)

	_, err = credstore.NewNameRouter(resolvers, map[string][]string{"": {"a"}})
	require.Error(t, err)

	_, err = credstore.NewNameRouter(resolvers, map[string][]string{"op": {"ghost"}})
	require.Error(t, err)

	_, err = credstore.NewNameRouter(resolvers, map[string][]string{"op": {"a", "a"}})
	require.Error(t, err)
}

func TestNameRouter_MalformedRefErrors(t *testing.T) {
	t.Parallel()

	r, err := credstore.NewNameRouter(
		map[string]broker.Resolver{"a": &stubResolver{values: map[string]string{}}},
		map[string][]string{"op": {"a"}},
	)
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "not-a-uri")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "malformed"))
}
