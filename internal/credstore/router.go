package credstore

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/mmartinez/postern/internal/broker"
)

// ErrUnknownScheme is returned by NameRouter.Resolve when a secret-ref's
// scheme has no resolver in the router. Callers can errors.Is against it to
// distinguish routing failures from resolver-internal errors.
var ErrUnknownScheme = errors.New("credstore: no resolver for secret_ref scheme")

// NameRouter is the broker.Resolver handed to broker.Hook. It dispatches
// each Resolve call to the resolver of one configured credstore, keyed by
// the credstore NAME (not its provider's URI scheme), so two credstores of
// the same vendor can coexist.
//
// A rule references a store either explicitly — grammar
// `<scheme>+<name>://<rest>` (e.g. op+team://Vault/Item/field) — or
// implicitly with a plain reference (op://...), which routes only when
// exactly one configured credstore resolves that scheme and is ambiguous
// otherwise. The router parses the qualifier itself and delegates the
// STRIPPED reference (plain "op://..."), so every underlying resolver keeps
// seeing vendor-shaped refs and the broker's vaultID stays "" per the
// documented Resolver contract.
//
// The maps are fixed at construction; a configuration change at runtime
// means swapping in a new router via the reload path (see broker.RunReloader).
type NameRouter struct {
	byName   map[string]broker.Resolver // credstore name → resolver
	byScheme map[string][]string        // sorted scheme → credstore names resolving it
}

// NewNameRouter builds a name-keyed router. byName must be non-empty and
// free of nil resolvers or empty names; byScheme entries must be non-empty,
// sorted, duplicate-free name lists whose members all exist in byName.
// Invalid input is an error so a misconfigured caller fails closed at boot
// rather than at the first request.
func NewNameRouter(byName map[string]broker.Resolver, byScheme map[string][]string) (*NameRouter, error) {
	if len(byName) == 0 {
		return nil, errors.New("credstore: name router requires at least one resolver")
	}
	cp := make(map[string]broker.Resolver, len(byName))
	for k, v := range byName {
		if k == "" {
			return nil, errors.New("credstore: name router rejects empty credstore name")
		}
		if v == nil {
			return nil, fmt.Errorf("credstore: nil resolver for credstore %q", k)
		}
		cp[k] = v
	}
	schemeIdx := make(map[string][]string, len(byScheme))
	for scheme, names := range byScheme {
		if scheme == "" {
			return nil, errors.New("credstore: name router rejects empty scheme key")
		}
		sorted := slices.Clone(names)
		slices.Sort(sorted)
		for i := 1; i < len(sorted); i++ {
			if sorted[i] == sorted[i-1] {
				return nil, fmt.Errorf("credstore: scheme %q lists credstore %q more than once", scheme, sorted[i])
			}
		}
		for _, name := range sorted {
			if _, ok := cp[name]; !ok {
				return nil, fmt.Errorf("credstore: scheme %q lists unknown credstore %q", scheme, name)
			}
		}
		schemeIdx[scheme] = sorted
	}
	return &NameRouter{byName: cp, byScheme: schemeIdx}, nil
}

// Names returns the sorted credstore names resolving scheme. Used by boot
// guards and display surfaces that need the same ambiguity picture as
// Resolve without issuing one.
func (r *NameRouter) Names(scheme string) []string {
	return r.byScheme[scheme]
}

// Resolve extracts the qualified ref's scheme and credstore name, picks the
// named store's resolver (or, for an unqualified ref, the sole resolver for
// the scheme), and delegates the stripped plain reference. Refs missing the
// "://" separator fail with a clear error so a misconfigured rule surfaces
// immediately rather than as a downstream resolver error.
func (r *NameRouter) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	scheme, name, ok := ParseQualifiedRef(secretRef)
	if !ok {
		return "", fmt.Errorf("credstore: malformed secret_ref %q (missing scheme)", secretRef)
	}
	var sub broker.Resolver
	if name != "" {
		var found bool
		sub, found = r.byName[name]
		if !found {
			return "", fmt.Errorf("%w: credstore %q is not configured", ErrUnknownScheme, name)
		}
	} else {
		names := r.byScheme[scheme]
		switch len(names) {
		case 0:
			return "", fmt.Errorf("%w: %q", ErrUnknownScheme, scheme)
		case 1:
			sub = r.byName[names[0]]
		default:
			return "", fmt.Errorf(
				"credstore: unqualified secret_ref scheme %q is ambiguous: credstores %q and %q both resolve it; qualify the reference as <scheme>+<name>:// (e.g., %s+%s://)",
				scheme, names[0], names[1], scheme, names[0],
			)
		}
	}
	return sub.Resolve(ctx, vaultID, StripQualifier(secretRef))
}
