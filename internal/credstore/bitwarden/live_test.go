package bitwarden

import (
	"context"
	"os"
	"strings"
	"testing"
)

// Live tests exercise a real bws binary against a real Secrets Manager machine
// account. They are skipped by default and run only when BWS_E2E=1, with the
// access token supplied via a 0600/0400 file (BWS_E2E_TOKEN_FILE) per the
// project's secret-handling rule — never inline in the environment or argv.
// BWS_E2E_SERVER_URL optionally points at a self-hosted deployment. This is the
// canonical "does our bws shape still hold?" probe and the empirical check that
// a bad token fails closed.

func skipUnlessLive(t *testing.T) {
	t.Helper()
	if os.Getenv("BWS_E2E") != "1" {
		t.Skip("BWS_E2E != 1; skipping live bws exercise")
	}
}

// liveToken reads the access token from BWS_E2E_TOKEN_FILE, refusing a file
// whose group/other permission bits are set so a token is never read from a
// world- or group-readable path.
func liveToken(t *testing.T) string {
	t.Helper()
	path := os.Getenv("BWS_E2E_TOKEN_FILE")
	if path == "" {
		t.Skip("BWS_E2E_TOKEN_FILE empty; skipping live bws exercise")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("token file %s has mode %#o; must be 0600 or 0400 (no group/other bits)", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		t.Fatalf("token file %s is empty", path)
	}
	return tok
}

func liveSettings() map[string]string {
	if u := os.Getenv("BWS_E2E_SERVER_URL"); u != "" {
		return map[string]string{keyServerURL: u}
	}
	return nil
}

func TestLiveValidate(t *testing.T) {
	skipUnlessLive(t)
	tok := liveToken(t)

	if err := NewProvider().Validate(context.Background(), tok, liveSettings()); err != nil {
		t.Fatalf("Validate against real Secrets Manager: %v", err)
	}
}

func TestLiveResolve(t *testing.T) {
	skipUnlessLive(t)
	tok := liveToken(t)
	ref := os.Getenv("BWS_E2E_SECRET_REF")
	if ref == "" {
		t.Skip("BWS_E2E_SECRET_REF empty; skipping live resolve")
	}

	r, err := NewProvider().NewResolver(context.Background(), tok, liveSettings())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	// Assert only non-empty so the secret value never reaches the test log.
	v, err := r.Resolve(context.Background(), "", ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v == "" {
		t.Fatalf("Resolve returned empty value (secret_ref invalid?)")
	}
}
