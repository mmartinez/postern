//go:build !linux && !darwin

package cli

import "errors"

// execProcess fails on platforms without syscall.Exec. Postern targets Linux
// (amd64/arm64) today; the build tag keeps a hypothetical Windows build
// compiling even though `postern exec` cannot replace the process there.
func execProcess(_ string, _, _ []string) error {
	return errors.New("postern exec is not supported on this platform; use a process manager to inject the environment instead")
}
