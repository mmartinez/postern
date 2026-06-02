package token_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mmartinez/postern/internal/token"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewMemoryStore()

	const (
		account = "op-sa:default"
		secret  = "ops_eyJhbGciOiJFUzI1NiJ9.PAYLOAD.a3F2"
	)

	if err := s.Set(ctx, account, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := s.Get(ctx, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != secret {
		t.Fatalf("Get = %q, want %q", got, secret)
	}
}

func TestMemoryStoreGetMissing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewMemoryStore()

	_, err := s.Get(ctx, "missing")
	if !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
}

func TestMemoryStoreOverwrite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewMemoryStore()

	if err := s.Set(ctx, "acct", "first"); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := s.Set(ctx, "acct", "second"); err != nil {
		t.Fatalf("Set second: %v", err)
	}

	got, err := s.Get(ctx, "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "second" {
		t.Fatalf("Get = %q, want %q (overwrite failed)", got, "second")
	}
}

func TestMemoryStoreDelete(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewMemoryStore()

	if err := s.Set(ctx, "acct", "val"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete(ctx, "acct"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := s.Get(ctx, "acct")
	if !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("post-Delete Get err = %v, want ErrNotFound", err)
	}
}

func TestMemoryStoreDeleteMissing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewMemoryStore()

	// Deleting a missing entry should be idempotent — surfacing ErrNotFound
	// would force CLI callers to special-case "already removed" cleanup.
	if err := s.Delete(ctx, "missing"); err != nil {
		t.Fatalf("Delete(missing) = %v, want nil", err)
	}
}

func TestMemoryStoreBackendName(t *testing.T) {
	t.Parallel()

	s := token.NewMemoryStore()
	if got := s.Backend(); got != "memory" {
		t.Fatalf("Backend() = %q, want %q", got, "memory")
	}
}

func TestMemoryStoreSeparateAccounts(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := token.NewMemoryStore()

	if err := s.Set(ctx, "a", "alpha"); err != nil {
		t.Fatalf("Set a: %v", err)
	}
	if err := s.Set(ctx, "b", "beta"); err != nil {
		t.Fatalf("Set b: %v", err)
	}

	gotA, err := s.Get(ctx, "a")
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	gotB, err := s.Get(ctx, "b")
	if err != nil {
		t.Fatalf("Get b: %v", err)
	}

	if gotA != "alpha" || gotB != "beta" {
		t.Fatalf("got (%q, %q), want (alpha, beta)", gotA, gotB)
	}
}

// Compile-time check that MemoryStore satisfies the Store interface.
var _ token.Store = (*token.MemoryStore)(nil)
