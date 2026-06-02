package token

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoBackend is returned by NoopStore operations to signal that no OS
// keyring backend was detected on the host. Callers should branch with
// errors.Is rather than string-matching the message.
var ErrNoBackend = errors.New("no os keychain backend available")

// errNoBackendDetail wraps ErrNoBackend with the user-facing remediation
// hint. It is the single error returned by every NoopStore method so that
// callers get both errors.Is(err, ErrNoBackend) for control flow and a
// human-readable message for output. The wording references the documented
// fallback (token.file in config.yaml) so a user staring at the CLI can act.
var errNoBackendDetail = fmt.Errorf(
	"%w: set token.source to \"file\" in config.yaml and mount a token.file, "+
		"or run postern on a host with a keychain",
	ErrNoBackend,
)

// NoopStore is the Store implementation returned when Probe reports no
// available backend (typically headless containers). Every operation
// returns errNoBackendDetail so callers can branch with errors.Is and
// users get an actionable error message.
//
// NoopStore is safe for concurrent use — it has no state.
type NoopStore struct{}

// NewNoopStore returns a NoopStore ready for use.
func NewNoopStore() *NoopStore { return &NoopStore{} }

// Set implements Store.
func (NoopStore) Set(_ context.Context, _, _ string) error { return errNoBackendDetail }

// Get implements Store.
func (NoopStore) Get(_ context.Context, _ string) (string, error) {
	return "", errNoBackendDetail
}

// Delete implements Store.
func (NoopStore) Delete(_ context.Context, _ string) error { return errNoBackendDetail }

// Backend implements Store.
func (NoopStore) Backend() string { return "none" }
