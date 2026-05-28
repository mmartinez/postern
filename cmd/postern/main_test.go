package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/version"
)

// TestVersionFlag verifies that `postern --version` writes the package version
// string to stdout. The version value comes from internal/version, which is
// designed to be overridden by ldflags at release build time. This test exercises
// only the cobra wiring; release-time ldflags are validated in CI.
func TestVersionFlag(t *testing.T) {
	t.Parallel()

	cmd := newRootCmd()
	cmd.SetArgs([]string{"--version"})

	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stdout)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("postern --version returned an error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, version.Version) {
		t.Fatalf("output does not contain version %q:\n%s", version.Version, out)
	}
}
