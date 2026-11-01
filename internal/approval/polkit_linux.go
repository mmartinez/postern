//go:build linux

package approval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/mmartinez/postern/internal/broker"
)

// ErrNoAgent means pkcheck found no authentication agent to show the dialog.
var ErrNoAgent = errors.New("no polkit authentication agent is running")

// maxStderr bounds how much pkcheck stderr is kept for an error message.
const maxStderr = 4096

// Polkit asks polkit, through pkcheck, to authorize ActionID for this
// process. The authentication agent shows the dialog.
type Polkit struct {
	path    string
	subject string
	err     error
}

// New returns the polkit approver for this process. A setup failure is kept
// and returned by every Approve call, so approval rules fail closed.
func New() broker.Approver {
	path, err := exec.LookPath("pkcheck")
	if err != nil {
		return &Polkit{err: fmt.Errorf("find pkcheck: %w", err)}
	}
	return newPolkit(path)
}

func newPolkit(path string) *Polkit {
	subject, err := processSubject()
	return &Polkit{path: path, subject: subject, err: err}
}

// processSubject returns this process as pid,start-time,uid. The start time
// pins the subject to this process even if its pid is later reused.
func processSubject() (string, error) {
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return "", fmt.Errorf("read process start time: %w", err)
	}
	// The command name in field 2 may contain spaces and parentheses.
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return "", errors.New("parse /proc/self/stat: no command name")
	}
	fields := strings.Fields(string(raw[end+1:]))
	// fields[0] is field 3; the start time is field 22.
	if len(fields) < 20 {
		return "", errors.New("parse /proc/self/stat: too few fields")
	}
	return fmt.Sprintf("%d,%s,%d", os.Getpid(), fields[19], os.Getuid()), nil
}

// Approve runs pkcheck with reason as the dialog text and maps its exit
// status to an outcome. Cancelling ctx terminates pkcheck, which closes the
// dialog.
func (p *Polkit) Approve(ctx context.Context, reason string) (broker.Outcome, error) {
	if p.err != nil {
		return broker.OutcomeUnavailable, p.err
	}
	var stderr headBuffer
	// polkit expands $(key) in the message, and an unterminated "$(" drops
	// the rest of it, so a request path could hide which agent is asking.
	// "%28" is how the path would percent-encode the parenthesis anyway.
	message := "postern is trying to " + strings.ReplaceAll(reason, "$(", "$%28") + "."
	cmd := exec.CommandContext(ctx, p.path, //nolint:gosec // path comes from LookPath; message is one argv entry, never shell-parsed
		"--action-id", ActionID,
		"--process", p.subject,
		"--allow-user-interaction",
		"--detail", "polkit.message", message,
	)
	cmd.Stderr = &stderr
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return broker.OutcomeUnavailable, fmt.Errorf("pkcheck: %w", ctxErr)
	}
	if err == nil {
		return broker.OutcomeApproved, nil
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return broker.OutcomeUnavailable, fmt.Errorf("run pkcheck: %w", err)
	}
	switch code := exit.ExitCode(); code {
	case 1:
		return broker.OutcomeDenied, nil
	case 2:
		return broker.OutcomeUnavailable, ErrNoAgent
	case 3:
		return broker.OutcomeDismissed, nil
	default:
		line, _, _ := strings.Cut(string(stderr.b), "\n")
		// A missing policy or one without this user as owner shows up here.
		return broker.OutcomeUnavailable, fmt.Errorf("pkcheck exit %d: %s (is the policy from `postern approval policy` installed?)", code, strings.TrimSpace(line))
	}
}

// headBuffer keeps the first maxStderr bytes written to it and drops the rest.
type headBuffer struct{ b []byte }

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := maxStderr - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}
