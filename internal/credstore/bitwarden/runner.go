package bitwarden

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
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
func (e *execRunner) run(ctx context.Context, args, env []string) ([]byte, error) {
	// bwsPath is resolved to an absolute path at construction (no PATH hijack)
	// and args are a fixed verb list plus a shape-checked id and non-secret URL
	// passed as argv (no shell), so there is no injection surface here.
	cmd := exec.CommandContext(ctx, e.bwsPath, args...) //nolint:gosec // see comment above
	cmd.Env = env
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// Discard stderr: this is a credential broker, and bws diagnostics could
	// echo request context. Keep that off the error path entirely so a secret
	// can never reach a log through a wrapped *exec.ExitError.
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("run bws: %w", err)
	}
	return stdout.Bytes(), nil
}
