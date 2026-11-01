package approval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
)

// fakePkcheck writes an executable script standing in for pkcheck. It records
// its arguments one per line in args, then runs body.
//
// The script is written under a temporary name and renamed into place so no
// open write handle remains on the inode that is executed. Tests that exec
// it must not call t.Parallel: a fork in a concurrent test can inherit the
// write fd and the exec then fails with ETXTBSY (golang/go#22220).
func fakePkcheck(t *testing.T, body string) (path, args string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "pkcheck")
	args = filepath.Join(dir, "args")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > '" + args + "'\n" + body + "\n"
	require.NoError(t, os.WriteFile(path+".tmp", []byte(script), 0o700))
	require.NoError(t, os.Rename(path+".tmp", path))
	return path, args
}

func TestPolkit_ExitCodes(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		want    broker.Outcome
		wantErr string
		wantIs  error
	}{
		{name: "authorized", body: "exit 0", want: broker.OutcomeApproved},
		{name: "not authorized", body: "exit 1", want: broker.OutcomeDenied},
		{name: "dismissed", body: "exit 3", want: broker.OutcomeDismissed},
		{name: "no agent", body: "exit 2", want: broker.OutcomeUnavailable, wantIs: ErrNoAgent},
		{
			name:    "error",
			body:    "printf 'Error checking for authorization: only trusted callers\\nsecond line\\n' >&2; exit 127",
			want:    broker.OutcomeUnavailable,
			wantErr: "Error checking for authorization: only trusted callers",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := fakePkcheck(t, tc.body)

			got, err := polkitAt(path).Approve(t.Context(), "send op://V/I/f to GET api.example.com/v1 for any client")

			require.Equal(t, tc.want, got)
			switch {
			case tc.wantIs != nil:
				require.ErrorIs(t, err, tc.wantIs)
			case tc.wantErr != "":
				require.ErrorContains(t, err, tc.wantErr, "the error carries pkcheck's first stderr line")
				require.NotContains(t, err.Error(), "second line")
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestPolkit_PassesSubjectAndMessage(t *testing.T) {
	path, args := fakePkcheck(t, "exit 0")
	_, err := polkitAt(path).Approve(t.Context(), "send op://V/I/f to GET api.example.com/v1 for any client")
	require.NoError(t, err)

	raw, err := os.ReadFile(args)
	require.NoError(t, err)
	got := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	require.Len(t, got, 8)
	require.Equal(t, []string{"--action-id", ActionID, "--process"}, got[:3])
	require.Regexp(t, `^`+strconv.Itoa(os.Getpid())+`,[0-9]+,`+strconv.Itoa(os.Getuid())+`$`, got[3])
	require.Equal(t, []string{
		"--allow-user-interaction",
		"--detail", "polkit.message",
		"postern is trying to send op://V/I/f to GET api.example.com/v1 for any client.",
	}, got[4:])
}

// TestPolkit_MessageNeverExpands covers polkit's $(key) expansion of the
// message. An unterminated "$(" makes polkit drop the rest of the text, so a
// request path could hide which agent is asking. No "$(" may reach polkit.
func TestPolkit_MessageNeverExpands(t *testing.T) {
	path, args := fakePkcheck(t, "exit 0")
	_, err := polkitAt(path).Approve(t.Context(), "send op://V/I/f to GET api.example.com/a$(polkit.message)/b$( for agent max")
	require.NoError(t, err)

	raw, err := os.ReadFile(args)
	require.NoError(t, err)
	got := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	msg := got[len(got)-1]
	require.NotContains(t, msg, "$(")
	require.True(t, strings.HasSuffix(msg, " for agent max."), "the agent must still close the message: %q", msg)
}

func TestPolkit_CancelKillsPkcheck(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "started")
	require.NoError(t, syscall.Mkfifo(fifo, 0o600))
	path, _ := fakePkcheck(t, "echo up > '"+fifo+"'; exec sleep 60")

	ctx, cancel := context.WithCancel(t.Context())
	type result struct {
		outcome broker.Outcome
		err     error
	}
	done := make(chan result, 1)
	go func() {
		o, err := polkitAt(path).Approve(ctx, "reason")
		done <- result{o, err}
	}()

	// Opening the read end blocks until pkcheck is running.
	started, err := os.ReadFile(fifo)
	require.NoError(t, err)
	require.Equal(t, "up\n", string(started))
	cancel()

	select {
	case r := <-done:
		require.Equal(t, broker.OutcomeUnavailable, r.outcome)
		require.True(t, errors.Is(r.err, context.Canceled), "got %v", r.err)
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not stop pkcheck")
	}
}

func TestPolkit_MissingBinaryIsUnavailable(t *testing.T) {
	t.Parallel()

	got, err := polkitAt(filepath.Join(t.TempDir(), "pkcheck")).Approve(t.Context(), "reason")
	require.Equal(t, broker.OutcomeUnavailable, got)
	require.Error(t, err)
}
