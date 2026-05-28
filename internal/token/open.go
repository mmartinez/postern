package token

import (
	"errors"
	"fmt"

	keyringlib "github.com/99designs/keyring"
)

// Open returns the most appropriate Store for the current host. It probes
// for available OS keyring backends and tries to open each in preference
// order. The first one that actually opens wins; if every detected backend
// fails (devcontainer's keyctl shim is a common offender) Open falls back
// to a NoopStore.
//
// The returned Store is always non-nil and safe to use. The returned error
// is non-nil only when degradation occurred — Probe reported one or more
// backends but none would open. Callers typically log the error and proceed
// with the returned Store; token subcommands will then surface ErrNoBackend
// on actual use.
func Open(serviceName string) (Store, error) {
	available := keyringlib.AvailableBackends()
	if len(available) == 0 {
		return NewNoopStore(), nil
	}

	present := make(map[keyringlib.BackendType]struct{}, len(available))
	for _, b := range available {
		present[b] = struct{}{}
	}

	var openErrs []error
	for _, b := range backendPreference {
		if _, ok := present[b]; !ok {
			continue
		}
		ring, err := keyringlib.Open(keyringlib.Config{
			ServiceName:     serviceName,
			AllowedBackends: []keyringlib.BackendType{b},
		})
		if err != nil {
			openErrs = append(openErrs, fmt.Errorf("open %s: %w", b, err))
			continue
		}
		return NewKeyringStore(ring, string(b)), nil
	}

	return NewNoopStore(), fmt.Errorf("no keyring backend could be opened: %w", errors.Join(openErrs...))
}
