//go:build linux || darwin

package cli

import (
	"os/exec"
	"syscall"
)

// setDaemonAttrs configures the re-exec'd child to detach from the
// controlling terminal via setsid. Without Setsid the daemonized process
// would receive SIGHUP when the launching shell exits.
func setDaemonAttrs(cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return nil
}
