//go:build !linux && !darwin

package cli

import (
	"github.com/mmartinez/postern/internal/approval"
	"github.com/mmartinez/postern/internal/broker"
)

// newApprover returns this platform's approval backend.
func newApprover() broker.Approver {
	return approval.NewUnsupported()
}
