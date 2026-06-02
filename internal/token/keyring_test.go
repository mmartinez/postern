package token_test

import (
	"context"
	"errors"
	"testing"

	keyringlib "github.com/99designs/keyring"

	"github.com/mmartinez/postern/internal/token"
)

func TestKeyringStoreRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ring := keyringlib.NewArrayKeyring(nil)
	s := token.NewKeyringStore(ring, "test-backend")

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

func TestKeyringStoreGetMissingMapsToErrNotFound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ring := keyringlib.NewArrayKeyring(nil)
	s := token.NewKeyringStore(ring, "test-backend")

	_, err := s.Get(ctx, "missing")
	if !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("Get(missing) err = %v, want ErrNotFound", err)
	}
}

func TestKeyringStoreDeleteIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ring := keyringlib.NewArrayKeyring(nil)
	s := token.NewKeyringStore(ring, "test-backend")

	// Deleting an entry that was never written must not surface ErrNotFound.
	if err := s.Delete(ctx, "missing"); err != nil {
		t.Fatalf("Delete(missing) = %v, want nil", err)
	}

	// Set then Delete then re-Delete must also succeed.
	if err := s.Set(ctx, "acct", "v"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete(ctx, "acct"); err != nil {
		t.Fatalf("first Delete: %v", err)
	}
	if err := s.Delete(ctx, "acct"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
}

func TestKeyringStoreBackendNameReflectsConstructor(t *testing.T) {
	t.Parallel()

	ring := keyringlib.NewArrayKeyring(nil)
	s := token.NewKeyringStore(ring, "secret-service")

	if got := s.Backend(); got != "secret-service" {
		t.Fatalf("Backend() = %q, want %q", got, "secret-service")
	}
}

func TestKeyringStoreOverwrite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ring := keyringlib.NewArrayKeyring(nil)
	s := token.NewKeyringStore(ring, "test-backend")

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
		t.Fatalf("Get = %q, want %q", got, "second")
	}
}

// failingKeyring is a hand-written keyring.Keyring that returns the
// configured error from every method. It exists to cover the non-ErrKeyNotFound
// error-wrap branches in KeyringStore, which ArrayKeyring's happy path
// can't exercise.
type failingKeyring struct{ err error }

func (f failingKeyring) Get(string) (keyringlib.Item, error) {
	return keyringlib.Item{}, f.err
}

func (failingKeyring) GetMetadata(string) (keyringlib.Metadata, error) {
	return keyringlib.Metadata{}, nil
}

func (f failingKeyring) Set(keyringlib.Item) error { return f.err }
func (f failingKeyring) Remove(string) error       { return f.err }
func (failingKeyring) Keys() ([]string, error)     { return nil, nil }

func TestKeyringStoreSetWrapsBackendError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("write protected")
	s := token.NewKeyringStore(failingKeyring{err: sentinel}, "broken")

	err := s.Set(context.Background(), "acct", "v")
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("Set err = %v, want wrap of %v", err, sentinel)
	}
}

func TestKeyringStoreGetWrapsNonNotFoundError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("connection refused")
	s := token.NewKeyringStore(failingKeyring{err: sentinel}, "broken")

	_, err := s.Get(context.Background(), "acct")
	if err == nil {
		t.Fatalf("Get returned nil error")
	}
	if errors.Is(err, token.ErrNotFound) {
		t.Fatalf("Get err = %v should not match ErrNotFound for a non-not-found backend error", err)
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("Get err = %v should wrap %v", err, sentinel)
	}
}

func TestKeyringStoreDeleteWrapsNonNotFoundError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("backend gone")
	s := token.NewKeyringStore(failingKeyring{err: sentinel}, "broken")

	err := s.Delete(context.Background(), "acct")
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("Delete err = %v, want wrap of %v", err, sentinel)
	}
}

func TestKeyringStoreDeleteMissingIsNoop(t *testing.T) {
	t.Parallel()

	// ErrKeyNotFound from the backend on a Remove must map to nil (idempotent).
	s := token.NewKeyringStore(failingKeyring{err: keyringlib.ErrKeyNotFound}, "test")
	if err := s.Delete(context.Background(), "missing"); err != nil {
		t.Fatalf("Delete on ErrKeyNotFound backend = %v, want nil", err)
	}
}
