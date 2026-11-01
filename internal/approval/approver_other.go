//go:build !linux && !darwin

package approval

import "github.com/mmartinez/postern/internal/broker"

// New returns nil: this platform has no approval backend, so the broker
// fails every approval rule closed. The config validator rejects approval
// blocks here before that can happen.
func New() broker.Approver {
	return nil
}
