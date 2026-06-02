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
// every PR. This is the canonical "is our SDK pin still right?" probe.
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

// TestLiveResolve exercises sdkResolver.Resolve against the real SDK and a
// real secret reference supplied via OP_E2E_SECRET_REF (e.g. one created
// just for the test in the same Service Account vault). Skipped unless
// OP_E2E=1 and both OP_SERVICE_ACCOUNT_TOKEN and OP_E2E_SECRET_REF are set.
//
// The returned value is asserted only as non-empty so the test can run
// against any vault layout without leaking the secret into logs.
func TestLiveResolve(t *testing.T) {
	if os.Getenv("OP_E2E") != "1" {
		t.Skip("OP_E2E != 1; skipping live SDK exercise")
	}
	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN empty; skipping live SDK exercise")
	}
	ref := os.Getenv("OP_E2E_SECRET_REF")
	if ref == "" {
		t.Skip("OP_E2E_SECRET_REF empty; skipping live resolve")
	}

	c, err := New(context.Background(), token, "live-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v, err := c.Resolver().Resolve(context.Background(), "", ref)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v == "" {
		t.Fatalf("Resolve returned empty value (secret_ref invalid?)")
	}
}
