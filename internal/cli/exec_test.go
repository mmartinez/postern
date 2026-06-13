package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/token"
)

// fakeResolver resolves a ref from a fixed map; a configured err short-circuits
// every call so a test can model a vault outage.
type fakeResolver struct {
	values map[string]string
	err    error
}

func (f fakeResolver) Resolve(_ context.Context, _, ref string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.values[ref]
	if !ok {
		return "", errors.New("no such ref: " + ref)
	}
	return v, nil
}

// recordingExec stands in for the real syscall.Exec seam so a test can assert
// what the child WOULD be launched with — and, crucially, that it is never
// launched at all when resolution fails closed.
type recordingExec struct {
	called  bool
	command string
	argv    []string
	env     []string
}

func (r *recordingExec) run(command string, argv, env []string) error {
	r.called = true
	r.command = command
	r.argv = argv
	r.env = env
	return nil
}

func allCacheable(string) bool { return true }

// The happy path: every ref resolves, the resolved values land in the child
// env, and a config entry overrides an inherited variable of the same name.
func TestRunExec_ResolvesMergesAndExecs(t *testing.T) {
	t.Parallel()

	r := fakeResolver{values: map[string]string{"op://a": "AAA", "op://b": "BBB"}}
	refs := map[string]string{"A_VAR": "op://a", "B_VAR": "op://b"}
	inherited := []string{"PATH=/bin", "A_VAR=old"}
	rec := &recordingExec{}

	err := runExec(context.Background(), r, refs, inherited, allCacheable, discardLogger(), rec.run, []string{"printenv", "A_VAR"})
	require.NoError(t, err)

	require.True(t, rec.called, "the child must be launched on success")
	require.Equal(t, "printenv", rec.command)
	require.Equal(t, []string{"printenv", "A_VAR"}, rec.argv)
	require.Contains(t, rec.env, "A_VAR=AAA")
	require.Contains(t, rec.env, "B_VAR=BBB")
	require.Contains(t, rec.env, "PATH=/bin")
	require.NotContains(t, rec.env, "A_VAR=old", "a config env entry must override the inherited value")
}

// Fail closed: if any secret fails to resolve, the child is never launched —
// a partially-resolved environment is worse than not running at all.
func TestRunExec_FailClosed_ResolveError_NoExec(t *testing.T) {
	t.Parallel()

	rec := &recordingExec{}
	err := runExec(context.Background(), fakeResolver{err: errors.New("vault down")},
		map[string]string{"A_VAR": "op://a"}, nil, allCacheable, discardLogger(), rec.run, []string{"true"})

	require.Error(t, err)
	require.False(t, rec.called, "must not exec the child when a secret fails to resolve (fail closed)")
}

// A non-cacheable ref (e.g. an OTP) cannot survive an exec-and-replace, so it
// is rejected before any child is launched.
func TestRunExec_RejectsNonCacheable_NoExec(t *testing.T) {
	t.Parallel()

	neverCacheable := func(string) bool { return false }
	rec := &recordingExec{}
	err := runExec(context.Background(), fakeResolver{values: map[string]string{"op://otp": "x"}},
		map[string]string{"OTP": "op://otp"}, nil, neverCacheable, discardLogger(), rec.run, []string{"true"})

	require.Error(t, err)
	require.Contains(t, err.Error(), "non-cacheable")
	require.False(t, rec.called)
}

// Resolved secret values must never reach the logs; only the masked
// fingerprint may appear.
func TestRunExec_MasksSecretInLogs(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	const secret = "SUPERSECRETVALUE"
	rec := &recordingExec{}

	err := runExec(context.Background(), fakeResolver{values: map[string]string{"op://a": secret}},
		map[string]string{"A_VAR": "op://a"}, nil, allCacheable, logger, rec.run, []string{"true"})
	require.NoError(t, err)

	require.NotContains(t, buf.String(), secret, "the raw secret must never appear in logs")
	require.Contains(t, buf.String(), token.Fingerprint(secret), "logs should reference the masked fingerprint")
}

// mergeEnv overlays resolved values onto the inherited environment, replacing
// (not duplicating) any inherited variable of the same name.
func TestMergeEnv_OverridesInherited(t *testing.T) {
	t.Parallel()

	out := mergeEnv([]string{"PATH=/bin", "X=old"}, map[string]string{"X": "new", "Y": "y"})
	require.Contains(t, out, "PATH=/bin")
	require.Contains(t, out, "X=new")
	require.Contains(t, out, "Y=y")
	require.NotContains(t, out, "X=old")
}

// assertEnvRoutable is the boot-time guard mirroring assertRulesRoutable: an
// env value whose scheme no configured credstore resolves must error before any
// resolve, not mid-injection.
func TestAssertEnvRoutable(t *testing.T) {
	t.Parallel()

	resolvers := map[string]broker.Resolver{"op": nil}
	require.NoError(t, assertEnvRoutable(map[string]string{"A_VAR": "op://a"}, resolvers))

	err := assertEnvRoutable(map[string]string{"A_VAR": "bw://a"}, resolvers)
	require.Error(t, err)
	require.Contains(t, err.Error(), "bw")
}
