package credstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/mmartinez/postern/internal/broker"
)

// ErrUnknownScheme is returned by SchemeRouter.Resolve when a secret-ref's
// scheme has no resolver in the router. Callers can errors.Is against it to
// distinguish routing failures from resolver-internal errors.
var ErrUnknownScheme = errors.New("credstore: no resolver for secret_ref scheme")

// SchemeRouter is a broker.Resolver that dispatches each Resolve call to a
// scheme-specific underlying resolver. The map is fixed at construction; a
// configuration change at runtime means swapping in a new router via the
// reload path (see broker.RunReloader).
type SchemeRouter struct {
	byScheme map[string]broker.Resolver
}

// NewSchemeRouter builds a router that dispatches by URI scheme. byScheme
// must be non-empty; nil or empty input is an error so a misconfigured
// caller fails closed at boot rather than at the first request.
func NewSchemeRouter(byScheme map[string]broker.Resolver) (*SchemeRouter, error) {
	if len(byScheme) == 0 {
		return nil, errors.New("credstore: scheme router requires at least one resolver")
	}
	cp := make(map[string]broker.Resolver, len(byScheme))
	for k, v := range byScheme {
		if k == "" {
			return nil, errors.New("credstore: scheme router rejects empty scheme key")
		}
		if v == nil {
			return nil, fmt.Errorf("credstore: nil resolver for scheme %q", k)
		}
		cp[k] = v
	}
	return &SchemeRouter{byScheme: cp}, nil
}

// Resolve extracts the URI scheme from secretRef and delegates to the
// matching resolver. Refs missing the "://" separator fail with a clear
// error so a misconfigured rule surfaces immediately rather than as a
// downstream resolver error.
func (r *SchemeRouter) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	i := strings.Index(secretRef, "://")
	if i <= 0 {
		return "", fmt.Errorf("credstore: malformed secret_ref %q (missing scheme)", secretRef)
	}
	scheme := secretRef[:i]
	sub, ok := r.byScheme[scheme]
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownScheme, scheme)
	}
	return sub.Resolve(ctx, vaultID, secretRef)
}
