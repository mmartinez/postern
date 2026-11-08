package keychain

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/99designs/keyring"
)

// resolver reads items from one opened store. mu serializes reads because the
// Secret Service backend replaces its session on every Get.
type resolver struct {
	mu   sync.Mutex
	ring keyring.Keyring
}

// Resolve returns the value stored under the item secretRef names. A
// non-empty vaultID fails closed: keychain refs carry the full item name.
func (r *resolver) Resolve(_ context.Context, vaultID, secretRef string) (string, error) {
	if vaultID != "" {
		return "", fmt.Errorf("vaultID-scoped resolution is not implemented (vaultID=%q)", vaultID)
	}
	name, err := itemName(secretRef)
	if err != nil {
		return "", err
	}
	r.mu.Lock()
	item, err := r.ring.Get(keyPrefix + name)
	r.mu.Unlock()
	switch {
	case errors.Is(err, keyring.ErrKeyNotFound):
		return "", fmt.Errorf("keychain item %q not found", name)
	case err != nil:
		return "", fmt.Errorf("keychain: read item %q: %w", name, err)
	case len(item.Data) == 0:
		return "", fmt.Errorf("keychain item %q is empty", name)
	}
	return string(item.Data), nil
}
