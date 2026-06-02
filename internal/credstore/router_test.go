package credstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"
)

var errStubMiss = errors.New("stub: no such secret_ref")

type stubResolver struct {
	values map[string]string
}

func (s *stubResolver) Resolve(_ context.Context, _, secretRef string) (string, error) {
	if v, ok := s.values[secretRef]; ok {
		return v, nil
	}
	return "", errStubMiss
}

func TestSchemeRouter_RoutesByScheme(t *testing.T) {
	t.Parallel()

	op := &stubResolver{values: map[string]string{
		"op://Vault/Item/field": "from-op",
	}}
	bw := &stubResolver{values: map[string]string{
		"bw://collection/item/field": "from-bw",
	}}

	r, err := credstore.NewSchemeRouter(map[string]broker.Resolver{
		"op": op,
		"bw": bw,
	})
	require.NoError(t, err)

	v, err := r.Resolve(context.Background(), "", "op://Vault/Item/field")
	require.NoError(t, err)
	require.Equal(t, "from-op", v)

	v, err = r.Resolve(context.Background(), "", "bw://collection/item/field")
	require.NoError(t, err)
	require.Equal(t, "from-bw", v)
}

func TestSchemeRouter_UnknownSchemeErrors(t *testing.T) {
	t.Parallel()

	r, err := credstore.NewSchemeRouter(map[string]broker.Resolver{
		"op": &stubResolver{values: map[string]string{}},
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "vault://x/y/z")
	require.Error(t, err)
	require.ErrorIs(t, err, credstore.ErrUnknownScheme)
}

func TestSchemeRouter_RejectsEmptyMap(t *testing.T) {
	t.Parallel()

	_, err := credstore.NewSchemeRouter(nil)
	require.Error(t, err)
}

func TestSchemeRouter_MalformedRefErrors(t *testing.T) {
	t.Parallel()

	r, err := credstore.NewSchemeRouter(map[string]broker.Resolver{
		"op": &stubResolver{values: map[string]string{}},
	})
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "", "not-a-uri")
	require.Error(t, err)
}
