package token_test

import (
	"testing"

	"github.com/mmartinez/postern/internal/token"
)

func TestProbeReturnsKnownLabel(t *testing.T) {
	t.Parallel()

	got := token.Probe()

	// Probe must return one of the documented labels. We don't pin the exact
	// value because it depends on host OS and runtime state; instead we
	// assert membership in the closed set. The devcontainer environment has
	// no keyring backend so "none" is the expected value there.
	allowed := map[string]bool{
		"none":           true,
		"keychain":       true,
		"secret-service": true,
		"wincred":        true,
		"kwallet":        true,
		"keyctl":         true,
		"pass":           true,
		"file":           true,
	}
	if !allowed[got] {
		t.Fatalf("Probe() = %q, not in allowed set %v", got, allowed)
	}
}

func TestProbeIsStable(t *testing.T) {
	t.Parallel()

	// Two back-to-back calls should agree — the probe must not flap based
	// on transient state.
	a := token.Probe()
	b := token.Probe()
	if a != b {
		t.Fatalf("Probe() not stable: first=%q, second=%q", a, b)
	}
}
