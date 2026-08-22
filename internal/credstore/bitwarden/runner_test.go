package bitwarden

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeRunner is a canned-output runner the resolver and provider tests inject
// so no real bws process is forked. It records the last invocation's args.
type fakeRunner struct {
	stdout  []byte
	err     error
	gotArgs []string
	gotEnv  []string
	calls   int
}

func (f *fakeRunner) run(_ context.Context, args, env []string) ([]byte, error) {
	f.calls++
	f.gotArgs = args
	f.gotEnv = env
	return f.stdout, f.err
}

var (
	_ runner = (*execRunner)(nil)
	_ runner = (*fakeRunner)(nil)
)

// writeScript drops an executable POSIX shell script into a temp dir and
// returns its path, standing in for the bws binary under test.
//
// The body is written to a temporary name and renamed onto the final path:
// on overlayfs (every devcontainer) a just-closed O_WRONLY handle can
// outlive close() long enough that an immediate fork/exec of the same inode
// fails with ETXTBSY ("text file busy"). Renaming swaps the dentry to a
// fresh inode no one holds open for writing, so the exec below is race-free
// without sleeps or retries.
// Tests that exec the script MUST NOT call t.Parallel: a fork in a
// concurrently running test can transiently inherit this script's
// write fd (fork happens before the writer's close), and the exec then
// fails with ETXTBSY ("text file busy"). See golang/go#22220.
func writeScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bws")
	tmp := filepath.Join(dir, "bws.tmp")
	require.NoError(t, os.WriteFile(tmp, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	require.NoError(t, os.Rename(tmp, p))
	return p
}

func TestFakeRunner_ReturnsCannedOutput(t *testing.T) {
	t.Parallel()

	want := []byte(`{"value":"x"}`)
	f := &fakeRunner{stdout: want}
	out, err := f.run(context.Background(), []string{"secret", "get"}, nil)
	require.NoError(t, err)
	require.Equal(t, want, out)
	require.Equal(t, []string{"secret", "get"}, f.gotArgs)

	sentinel := errors.New("boom")
	out, err = (&fakeRunner{err: sentinel}).run(context.Background(), nil, nil)
	require.ErrorIs(t, err, sentinel)
	require.Nil(t, out)
}

func TestExecRunner_CapturesStdoutOnSuccess(t *testing.T) {
	r := &execRunner{bwsPath: writeScript(t, `echo hello`)}
	out, err := r.run(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(out))
}

func TestExecRunner_MapsNonZeroExitToError(t *testing.T) {
	r := &execRunner{bwsPath: writeScript(t, `exit 3`)}
	out, err := r.run(context.Background(), nil, nil)
	require.Error(t, err)
	require.Empty(t, out)
}

func TestExecRunner_ForwardsArgsAndEnv(t *testing.T) {
	// The script echoes its first arg and a sentinel env var so the test can
	// assert both crossed the exec boundary intact.
	r := &execRunner{bwsPath: writeScript(t, `echo "$1 $POSTERN_TEST_VAR"`)}
	out, err := r.run(context.Background(), []string{"arg1"}, []string{"POSTERN_TEST_VAR=envval"})
	require.NoError(t, err)
	require.Equal(t, "arg1 envval\n", string(out))
}

func TestNewExecRunner_UsesOverridePath(t *testing.T) {
	t.Parallel()

	path := writeScript(t, `echo ok`)
	r, err := newExecRunner(path)
	require.NoError(t, err)
	require.Equal(t, path, r.bwsPath)
}

func TestNewExecRunner_LooksUpBwsOnPath(t *testing.T) {
	// Not parallel: mutates PATH via t.Setenv.
	dir := t.TempDir()
	p := filepath.Join(dir, "bws")
	tmp := filepath.Join(dir, "bws.tmp")
	require.NoError(t, os.WriteFile(tmp, []byte("#!/bin/sh\necho ok\n"), 0o755))
	// Same tmp-then-rename dance as writeScript: this path is exec'd by
	// newExecRunner's PATH lookup immediately after the write.
	require.NoError(t, os.Rename(tmp, p))
	t.Setenv("PATH", dir)

	r, err := newExecRunner("")
	require.NoError(t, err)
	require.Equal(t, p, r.bwsPath)
}

func TestNewExecRunner_MissingBinaryReturnsActionableError(t *testing.T) {
	t.Parallel()

	_, err := newExecRunner(filepath.Join(t.TempDir(), "does-not-exist"))
	require.ErrorIs(t, err, ErrBwsNotFound)
	require.Contains(t, err.Error(), "install.sh")
	require.Contains(t, err.Error(), "-bitwarden")
}
