package token_test

import (
	"testing"

	"github.com/mmartinez/postern/internal/token"
)

func TestOpenHeadlessReturnsNoop(t *testing.T) {
	t.Parallel()

	// On the devcontainer (no D-Bus, no Secret Service, no Keychain) Probe
	// reports "none" and Open must return a NoopStore-shaped Store rather
	// than failing — `postern --help` shouldn't blow up just because the
	// host has no keyring.
	//
	// We can't pin the exact type because hosts with a working backend
	// (CI's token-keyring-e2e job) get a KeyringStore here. So the
	// assertion is functional: Backend() should be either "none" or a
	// known backend label.
	s, err := token.Open("postern-open-test")
	// On hosts with no backend or where every detected backend fails to
	// open (devcontainer's keyctl shim is a known offender), Open must
	// still return a non-nil Store. A non-nil err is allowed: it carries
	// the open failures so the CLI can warn the user, but the returned
	// Store is always safe to call.
	if s == nil {
		t.Fatalf("Open returned nil Store (err = %v)", err)
	}
	switch s.Backend() {
	case "none", "keychain", "secret-service", "wincred", "kwallet", "keyctl", "pass", "file":
		// expected outcomes
	default:
		t.Fatalf("Open returned Store with unexpected Backend() = %q", s.Backend())
	}
}
