//go:build !linux && !darwin

package approval

import (
	"context"
	"fmt"
	"runtime"

	"github.com/mmartinez/postern/internal/broker"
)

// Unsupported is the approver on platforms without an approval backend.
// Every approval is unavailable, so approval rules fail closed. The config
// validator rejects approval blocks here before that can happen.
type Unsupported struct{}

// New returns the unsupported-platform approver.
func New() Unsupported {
	return Unsupported{}
}

// Approve reports the approval as unavailable.
func (Unsupported) Approve(context.Context, string) (broker.Outcome, error) {
	return broker.OutcomeUnavailable, fmt.Errorf("approval is not supported on %s", runtime.GOOS)
}
