package token

import (
	"context"
	"errors"
	"fmt"

	keyringlib "github.com/99designs/keyring"
)

// KeyringStore is the Store implementation backed by an OS keyring through
// the 99designs/keyring abstraction. Wrapping the keyring.Keyring interface
// (rather than constructing it inside) lets unit tests inject the package's
// own ArrayKeyring fake so the wrapper logic is exercisable without a real
// backend.
type KeyringStore struct {
	ring        keyringlib.Keyring
	backendName string
}

// NewKeyringStore returns a Store that persists tokens via ring. backendName
// is the label surfaced by Backend() and the `postern token status` output;
// it should match the keyring.BackendType the ring was opened with (e.g.
// "secret-service", "keychain", "wincred").
func NewKeyringStore(ring keyringlib.Keyring, backendName string) *KeyringStore {
	return &KeyringStore{ring: ring, backendName: backendName}
}

// Set implements Store. The token value is stored as raw bytes; the keyring
// library handles backend-specific encryption (the OS keychain, encrypted
// Secret Service collection, etc).
func (s *KeyringStore) Set(_ context.Context, account, tok string) error {
	if err := s.ring.Set(keyringlib.Item{
		Key:         account,
		Data:        []byte(tok),
		Label:       "postern: " + account,
		Description: "service-account token managed by postern",
	}); err != nil {
		return fmt.Errorf("keyring set: %w", err)
	}
	return nil
}

// Get implements Store. A missing entry surfaces as ErrNotFound so callers
// can branch with errors.Is regardless of which backend is in play.
func (s *KeyringStore) Get(_ context.Context, account string) (string, error) {
	item, err := s.ring.Get(account)
	if err != nil {
		if errors.Is(err, keyringlib.ErrKeyNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("keyring get: %w", err)
	}
	return string(item.Data), nil
}

// Delete implements Store. Removing a non-existent entry is treated as
// success so cleanup paths in the CLI stay idempotent.
func (s *KeyringStore) Delete(_ context.Context, account string) error {
	if err := s.ring.Remove(account); err != nil {
		if errors.Is(err, keyringlib.ErrKeyNotFound) {
			return nil
		}
		return fmt.Errorf("keyring remove: %w", err)
	}
	return nil
}

// Backend implements Store.
func (s *KeyringStore) Backend() string { return s.backendName }
