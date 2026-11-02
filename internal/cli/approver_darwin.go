//go:build darwin

package cli

import "github.com/mmartinez/postern/internal/approval"

// newApprover returns this platform's approval backend.
func newApprover() approval.LocalAuth {
	return approval.NewLocalAuth()
}
