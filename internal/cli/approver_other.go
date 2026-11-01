//go:build !linux && !darwin

package cli

import "github.com/mmartinez/postern/internal/approval"

// newApprover returns this platform's approval backend.
func newApprover() approval.Unsupported {
	return approval.NewUnsupported()
}
