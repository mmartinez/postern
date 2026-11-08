package keychain

import (
	"context"
	"errors"
	"fmt"

	"github.com/99designs/keyring"
)

// resolver reads items from one opened store. Reads go through the
// provider's sem: the Secret Service backend replaces its session on every
// Get, so reads must not overlap.
type resolver struct {
	sem  chan struct{}
	ring keyring.Keyring
}

// Resolve returns the value stored under the item secretRef names. A
// non-empty vaultID fails closed: keychain refs carry the full item name.
func (r *resolver) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	if vaultID != "" {
		return "", fmt.Errorf("vaultID-scoped resolution is not implemented (vaultID=%q)", vaultID)
	}
	name, err := itemName(secretRef)
	if err != nil {
		return "", err
	}
	item, err := bounded(ctx, r.sem, func() (keyring.Item, error) { return r.ring.Get(keyPrefix + name) })
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

// bounded runs fn once sem is free and returns its result, or ctx's error
// once ctx ends. The store API takes no context, so an abandoned call (an
// unanswered unlock prompt, a hung daemon) finishes in the background and
// keeps sem until it returns: later calls wait for it only until their own
// deadline, so at most one native call is ever in flight.
func bounded[T any](ctx context.Context, sem chan struct{}, fn func() (T, error)) (T, error) {
	var zero T
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return zero, ctx.Err()
	}
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		defer func() { <-sem }()
		v, err := fn()
		done <- result{v, err}
	}()
	select {
	case res := <-done:
		return res.v, res.err
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}
