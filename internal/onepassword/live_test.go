package onepassword

import (
	"context"
	"os"
	"testing"
)

// TestLiveHealthCheck exercises the real credential-vendor SDK against a
// real service-account token. Skipped by default; runs only when OP_E2E=1
// is set in the environment AND OP_SERVICE_ACCOUNT_TOKEN is non-empty.
//
// The CI job op-live (.github/workflows/ci.yml) sets both, gated behind a
// workflow_dispatch `run_op_live=true` input so the vendor API isn't hit on
// every PR. This is the canonical "is our SDK pin still right?" probe per
// SPEC §12 and the CP2 review gate.
func TestLiveHealthCheck(t *testing.T) {
	if os.Getenv("OP_E2E") != "1" {
		t.Skip("OP_E2E != 1; skipping live SDK exercise")
	}
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN empty; skipping live SDK exercise")
	}

	c, err := New(context.Background(), token, "live-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}
