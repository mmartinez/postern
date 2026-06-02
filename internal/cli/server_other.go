//go:build !linux && !darwin

package cli

import (
	"errors"
	"os/exec"
)

// setDaemonAttrs returns an error on platforms that don't expose Setsid
// through syscall.SysProcAttr. Linux is the only supported target today;
// the build tag exists so that a hypothetical Windows build still compiles
// even though `-d` won't work there.
func setDaemonAttrs(_ *exec.Cmd) error {
	return errors.New("--daemon is not supported on this platform; use a process manager (systemd, supervisord) instead")
}
