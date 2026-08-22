package bitwarden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// ErrBwsNotFound is returned by newExecRunner when the bws binary cannot be
// located, so a misconfigured deployment fails closed at boot with an
// actionable message rather than a bare exec error on the first request.
var ErrBwsNotFound = errors.New("bws binary not found")

// runner abstracts a single bws CLI invocation. The production impl shells out
// via os/exec; tests inject a fake returning canned output so no real bws
// process is forked. Defining this interface in the consumer package is the
// accepted exception for wrapping an external dependency (here, a subprocess).
type runner interface {
	run(ctx context.Context, args, env []string) (stdout []byte, err error)
}

// execRunner runs the resolved bws binary. The absolute path is fixed at
// construction so a PATH change at request time cannot hijack the binary.
type execRunner struct {
	bwsPath string
}

// newExecRunner resolves bws to an absolute path once: bwsPathOverride when
// set, otherwise the first bws on PATH. A missing binary is wrapped with
// ErrBwsNotFound and a message pointing at the install routes.
func newExecRunner(bwsPathOverride string) (*execRunner, error) {
	candidate := bwsPathOverride
	if candidate == "" {
		candidate = "bws"
	}
	path, err := exec.LookPath(candidate)
	if err != nil {
		return nil, fmt.Errorf("%w: install it with install.sh or use the postern -bitwarden image, or set settings.bws_path (%v)", ErrBwsNotFound, err)
	}
	return &execRunner{bwsPath: path}, nil
}

// run executes the bws binary with args and a fully-specified env, returning
// captured stdout. A non-zero exit maps to a wrapped error.
//
// A start failure with ETXTBSY is retried briefly: the errno means another
// handle still has the binary open for writing, which happens legitimately
// while a bws upgrade replaces the binary mid-request, and transiently under
// heavy concurrent fork pressure on overlayfs containers (observed in the
// test suite writing fresh fake binaries). Three attempts over ~75ms bounds
// the added latency; any other error, or a persistent ETXTBSY, fails closed
// immediately as before.
func (e *execRunner) run(ctx context.Context, args, env []string) ([]byte, error) {
	// bwsPath is resolved to an absolute path at construction (no PATH hijack)
	// and args are a fixed verb list plus a shape-checked id and non-secret URL
	// passed as argv (no shell), so there is no injection surface here.
	//
	// The command is rebuilt on every attempt: exec.Cmd is single-use, and the
	// retry below needs a fresh Start/Wait cycle each time.
	buildCmd := func() *exec.Cmd {
		cmd := exec.CommandContext(ctx, e.bwsPath, args...) //nolint:gosec // see comment above
		cmd.Env = env
		cmd.Stderr = io.Discard
		return cmd
	}

	const attempts = 3
	var stdout bytes.Buffer
	var err error
	for i := range attempts {
		stdout.Reset()
		cmd := buildCmd()
		cmd.Stdout = &stdout
		if err = cmd.Run(); !errors.Is(err, syscall.ETXTBSY) {
			break
		}
		if last := attempts - 1; i < last {
			select {
			case <-ctx.Done():
			case <-time.After(25 * time.Millisecond):
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("run bws: %w", err)
	}
	return stdout.Bytes(), nil
}
