package keychain

import (
	"context"
	"errors"
	"fmt"

	"github.com/99designs/keyring"
)

// resolver reads items from one opened store. sem admits one store read at a
// time, because the Secret Service backend replaces its session on every Get.
type resolver struct {
	sem  chan struct{}
	ring keyring.Keyring
}

func newResolver(ring keyring.Keyring) *resolver {
	return &resolver{sem: make(chan struct{}, 1), ring: ring}
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
	item, err := r.get(ctx, keyPrefix+name)
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

// get waits for the store and reads key, giving up when ctx ends. A read
// abandoned mid-call keeps the store until it returns, so later reads wait at
// most until their own deadline rather than queueing behind it.
func (r *resolver) get(ctx context.Context, key string) (keyring.Item, error) {
	select {
	case r.sem <- struct{}{}:
	case <-ctx.Done():
		return keyring.Item{}, ctx.Err()
	}
	return read(ctx, func() (keyring.Item, error) {
		defer func() { <-r.sem }()
		return r.ring.Get(key)
	})
}

// read runs get and returns its result, or ctx's error once ctx ends. The
// store API takes no context, so an abandoned call (an unanswered unlock
// prompt, a hung daemon) finishes in the background.
func read(ctx context.Context, get func() (keyring.Item, error)) (keyring.Item, error) {
	type result struct {
		item keyring.Item
		err  error
	}
	done := make(chan result, 1)
	go func() {
		item, err := get()
		done <- result{item, err}
	}()
	select {
	case res := <-done:
		return res.item, res.err
	case <-ctx.Done():
		return keyring.Item{}, ctx.Err()
	}
}
