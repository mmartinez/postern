package token

import (
	"context"
	"errors"
	"sync"
)

// ErrNotFound is returned by Store.Get when the requested account has no
// stored token. Callers should inspect with errors.Is rather than matching the
// message text.
var ErrNotFound = errors.New("token not found")

// Store is the backend-neutral surface the CLI and runtime use to persist and
// retrieve the credential-vendor service-account token. Concrete
// implementations include MemoryStore (this file, for tests) and the
// 99designs/keyring-backed real store.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Set stores token under account, overwriting any previous value.
	Set(ctx context.Context, account, token string) error

	// Get returns the token previously stored for account. It returns
	// ErrNotFound if no such entry exists.
	Get(ctx context.Context, account string) (string, error)

	// Delete removes the entry for account. Deleting a non-existent
	// account is a no-op and must not return ErrNotFound.
	Delete(ctx context.Context, account string) error

	// Backend returns a short identifier for the underlying storage
	// mechanism, e.g. "keychain", "secret-service", or "memory". It is
	// used for the `postern token status` output and for audit log
	// context, never for control flow.
	Backend() string
}

// MemoryStore is an in-process Store backed by a map. It is intended for unit
// tests and headless CI scenarios where no OS keychain is available; the
// production keychain-backed Store lives alongside it.
//
// MemoryStore is safe for concurrent use.
type MemoryStore struct {
	mu   sync.Mutex
	data map[string]string
}

// NewMemoryStore returns an empty MemoryStore ready for use.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: make(map[string]string)}
}

// Set implements Store.
func (s *MemoryStore) Set(_ context.Context, account, tok string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[account] = tok
	return nil
}

// Get implements Store.
func (s *MemoryStore) Get(_ context.Context, account string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[account]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Delete implements Store. Missing accounts are silently accepted to keep
// cleanup paths in the CLI idempotent.
func (s *MemoryStore) Delete(_ context.Context, account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, account)
	return nil
}

// Backend implements Store.
func (s *MemoryStore) Backend() string { return "memory" }
