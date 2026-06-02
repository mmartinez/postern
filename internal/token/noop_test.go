package token_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/token"
)

func TestNoopStoreBackendName(t *testing.T) {
	t.Parallel()

	s := token.NewNoopStore()
	if got := s.Backend(); got != "none" {
		t.Fatalf("Backend() = %q, want %q", got, "none")
	}
}

func TestNoopStoreOperationsReturnErrNoBackend(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewNoopStore()

	if err := s.Set(ctx, "acct", "value"); !errors.Is(err, token.ErrNoBackend) {
		t.Fatalf("Set err = %v, want ErrNoBackend", err)
	}
	if _, err := s.Get(ctx, "acct"); !errors.Is(err, token.ErrNoBackend) {
		t.Fatalf("Get err = %v, want ErrNoBackend", err)
	}
	if err := s.Delete(ctx, "acct"); !errors.Is(err, token.ErrNoBackend) {
		t.Fatalf("Delete err = %v, want ErrNoBackend", err)
	}
}

func TestNoopStoreErrorMessageIsActionable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewNoopStore()

	err := s.Set(ctx, "acct", "value")
	if err == nil {
		t.Fatalf("Set returned nil error")
	}
	// The error message must tell the user *why* and at least hint at a
	// remediation — a bare "not supported" leaves them stuck.
	msg := err.Error()
	for _, keyword := range []string{"keychain", "token.file"} {
		if !strings.Contains(msg, keyword) {
			t.Errorf("error message %q missing keyword %q", msg, keyword)
		}
	}
}

// Compile-time check that NoopStore satisfies Store.
var _ token.Store = (*token.NoopStore)(nil)
