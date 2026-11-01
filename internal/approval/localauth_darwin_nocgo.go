//go:build darwin && !cgo

package approval

import (
	"context"
	"errors"

	"github.com/mmartinez/postern/internal/broker"
)

// errNoCgo explains why a build without cgo cannot show the dialog.
var errNoCgo = errors.New("this build has no cgo, so it cannot use LocalAuthentication")

// LocalAuth stands in for the LocalAuthentication approver in a build without
// cgo. Every approval is unavailable, so approval rules fail closed.
type LocalAuth struct{}

// New returns the stand-in approver.
func New() LocalAuth {
	return LocalAuth{}
}

// Approve reports the approval as unavailable.
func (LocalAuth) Approve(context.Context, string) (broker.Outcome, error) {
	return broker.OutcomeUnavailable, errNoCgo
}
