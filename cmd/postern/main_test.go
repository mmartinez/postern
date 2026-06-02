package main

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/version"
)

// helpColumnLimit pins the acceptance criterion that every command's --help
// output must fit in an 80-col terminal. Cobra wraps usage / flag lines
// itself; this gate catches hand-written Long / Example blocks where
// line breaks are author-controlled.
const helpColumnLimit = 80

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

// TestHelpOutputs_FitInEightyCols walks every command in the cobra tree,
// renders --help, and fails if any rendered line is wider than 80 cols.
// This catches both author-written Long/Example blocks and flag-usage
// lines synthesized by cobra from too-long Flag descriptions.
func TestHelpOutputs_FitInEightyCols(t *testing.T) {
	t.Parallel()

	walk(t, newRootCmd())
}

func walk(t *testing.T, c *cobra.Command) {
	t.Helper()
	t.Run(c.CommandPath(), func(t *testing.T) {
		help := renderHelp(t, c)
		for i, line := range strings.Split(help, "\n") {
			if n := visualWidth(line); n > helpColumnLimit {
				t.Errorf("%s --help line %d is %d cols (>%d): %q", c.CommandPath(), i+1, n, helpColumnLimit, line)
			}
		}
	})
	for _, sub := range c.Commands() {
		walk(t, sub)
	}
}

func renderHelp(t *testing.T, c *cobra.Command) string {
	t.Helper()
	var buf bytes.Buffer
	c.SetOut(&buf)
	c.SetErr(&buf)
	if err := c.Help(); err != nil {
		t.Fatalf("%s.Help(): %v", c.CommandPath(), err)
	}
	return buf.String()
}

// visualWidth approximates terminal column width as a rune count. This
// is accurate for ASCII and most Latin-script Unicode; CJK and emoji
// (which occupy 2 columns each) would need golang.org/x/text/width or a
// runewidth package for true visual width. RuneCount avoids the
// byte-vs-character mismatch len() would introduce on the first
// multi-byte char in a Long/Example block.
func visualWidth(s string) int { return utf8.RuneCountInString(s) }
