//go:build darwin && !cgo

package approval

import "github.com/mmartinez/postern/internal/broker"

// New returns nil: LocalAuthentication needs cgo, so a build without it has
// no approval backend and the broker fails every approval rule closed.
func New() broker.Approver {
	return nil
}
