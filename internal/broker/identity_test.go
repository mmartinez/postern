package broker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

func TestIdentitySnapshotAndRevocation(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	agents := []config.Agent{{Name: "agent", KeySHA256: hash}}
	e := NewEngine(nil)
	require.NoError(t, e.Publish(nil, agents))
	p := e.Authenticate("agent", key)
	require.NotNil(t, p)
	require.Nil(t, e.Authenticate("unknown", key))
	require.Nil(t, e.Authenticate("agent", "invalid"))
	var closed atomic.Int32
	ctx, release, ok := e.Admit(context.Background(), p, func() { closed.Add(1) })
	require.True(t, ok)
	defer release()
	require.NoError(t, e.Publish(nil, agents))
	require.Same(t, p, e.Authenticate("agent", key))
	require.NoError(t, ctx.Err())
	require.NoError(t, e.Publish(nil, nil))
	require.ErrorIs(t, ctx.Err(), context.Canceled)
	require.EqualValues(t, 1, closed.Load())
	_, cleanup, ok := e.Admit(context.Background(), p, func() { t.Error("revoked admission registered") })
	cleanup()
	require.False(t, ok)
	require.NoError(t, e.Publish(nil, agents))
	require.NotSame(t, p, e.Authenticate("agent", key))
	require.False(t, e.Current(p))
	before := e.Authenticate("agent", key)
	require.Error(t, e.Publish(nil, []config.Agent{{Name: "bad.name", KeySHA256: hash}}))
	require.Same(t, before, e.Authenticate("agent", key))
}

func TestRevokedRequestCannotResolve(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	rules := []Rule{{Host: "example.test", SecretRef: "test://ref", Injection: InjectSpec{Type: InjectHeader, Name: "Authorization", Template: "{{ CREDENTIAL }}"}}}
	e := NewEngine(rules)
	require.NoError(t, e.Publish(rules, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	p := e.Authenticate("agent", key)
	require.NoError(t, e.Publish(rules, nil))
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	r = r.WithContext(identity.WithPrincipal(r.Context(), p))
	res := &identityResolver{}
	hook := Hook(e, res, config.OnNoMatchBlock, 0, true, nil)
	response := hook(r)
	require.NotNil(t, response)
	defer func() { _ = response.Body.Close() }()
	require.Equal(t, http.StatusBadGateway, response.StatusCode)
	require.Zero(t, res.calls.Load())
}

type identityResolver struct{ calls atomic.Int32 }

func (r *identityResolver) Resolve(context.Context, string, string) (string, error) {
	r.calls.Add(1)
	return "", nil
}

func TestReleaseRemovesLifecycleWork(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	e := NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	p := e.Authenticate("agent", key)
	_, release, ok := e.Admit(context.Background(), p, func() { t.Error("released work closed") })
	require.True(t, ok)
	release()
	release()
	require.NoError(t, e.Publish(nil, nil))
}

func TestRequestContextHoldsNoEnrollmentSnapshot(t *testing.T) {
	t.Parallel()
	e := NewEngine(nil)
	r := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	hook := Hook(e, nil, config.OnNoMatchPassthrough, 0, true, nil) //nolint:bodyclose // Hook returns a callback, not a response; its result is closed below
	response := hook(r)
	if response != nil {
		defer func() { _ = response.Body.Close() }()
	}
	require.Nil(t, response)
	_, exposed := r.Context().Value(authorizationKey{}).(*engineSnapshot)
	require.False(t, exposed, "request context must not hold verifiers")
	require.True(t, e.authorizedSnapshot(r.Context()))
	require.NoError(t, e.Publish(nil, nil))
	require.True(t, e.authorizedSnapshot(r.Context()), "unaffected policy must retain request authorization")
}

func TestRotationKeepsUnaffectedIdentityAndPolicyLive(t *testing.T) {
	t.Parallel()
	keyA, hashA, err := identity.Generate()
	require.NoError(t, err)
	keyB, hashB, err := identity.Generate()
	require.NoError(t, err)
	_, rotatedHash, err := identity.Generate()
	require.NoError(t, err)
	e := NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "A", KeySHA256: hashA}, {Name: "B", KeySHA256: hashB}}))
	pA, pB := e.Authenticate("A", keyA), e.Authenticate("B", keyB)
	ctx := identity.WithPrincipal(context.Background(), pB)
	ctx = context.WithValue(ctx, authorizationKey{}, e.snapshot.Load().epoch)
	ctx, release, ok := e.Admit(ctx, pB, func() { t.Error("unaffected identity was closed") })
	require.True(t, ok)
	defer release()
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "A", KeySHA256: rotatedHash}, {Name: "B", KeySHA256: hashB}}))
	require.False(t, e.Current(pA))
	require.Same(t, pB, e.Authenticate("B", keyB))
	require.NoError(t, ctx.Err())
	require.True(t, e.authorizedSnapshot(ctx))
}
