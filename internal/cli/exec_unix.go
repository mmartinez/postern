//go:build linux || darwin

package cli

import (
	"fmt"
	"os/exec"
	"syscall"
)

// execProcess replaces the current process image with command (resolved
// against PATH) and argv, using env as the child's environment. On success it
// does not return: the kernel hands the process over to the child, so signals,
// the PID, and exit status all flow to it directly — the right shape under a
// process manager (systemd) and the devcontainer CLI. argv must include the
// command name as argv[0]; callers pass the post-`--` args verbatim.
func execProcess(command string, argv, env []string) error {
	path, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("locate command %q: %w", command, err)
	}
	// Launching a user-named command with a user-built environment is the whole
	// point of `postern exec`; the command and env come from the operator's
	// config and argv, not an untrusted request path.
	if err := syscall.Exec(path, argv, env); err != nil { //nolint:gosec // intentional exec wrapper; command + env are operator-supplied
		return fmt.Errorf("exec %q: %w", command, err)
	}
	return nil // unreachable: a successful Exec never returns.
}
