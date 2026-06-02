package credstore

import (
	"fmt"
	"strings"
	"sync"
)

// Registry tracks the Providers a process has linked in. It is safe for
// concurrent use; the typical pattern is one Register call per provider
// in an init() function, then read-only Lookup calls at request time.
type Registry struct {
	mu       sync.RWMutex
	byScheme map[string]Provider
	byName   map[string]Provider
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		byScheme: make(map[string]Provider),
		byName:   make(map[string]Provider),
	}
}

// Register adds p under its Scheme() and Name(). It panics on a nil
// provider, an empty scheme or name, or a duplicate of either. The panic
// mirrors database/sql's driver registry: registration is a static, boot-
// time invariant, and silently overriding a previously registered provider
// would be a footgun.
func (r *Registry) Register(p Provider) {
	if p == nil {
		panic("credstore: Register called with nil provider")
	}
	scheme := p.Scheme()
	if scheme == "" {
		panic("credstore: Register called with empty scheme")
	}
	name := p.Name()
	if name == "" {
		panic("credstore: Register called with empty name")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.byScheme[scheme]; dup {
		panic(fmt.Sprintf("credstore: scheme %q already registered", scheme))
	}
	if _, dup := r.byName[name]; dup {
		panic(fmt.Sprintf("credstore: provider name %q already registered", name))
	}
	r.byScheme[scheme] = p
	r.byName[name] = p
}

// ForName returns the Provider registered under name.
func (r *Registry) ForName(name string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byName[name]
	return p, ok
}

// ForScheme returns the Provider registered under scheme.
func (r *Registry) ForScheme(scheme string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byScheme[scheme]
	return p, ok
}

// ForSecretRef extracts the URI scheme from secretRef and returns the
// matching Provider. A secretRef must be of the form "<scheme>://<rest>";
// inputs missing the "://" separator return (nil, false) so callers can
// surface a clear "no provider for ref" error.
func (r *Registry) ForSecretRef(secretRef string) (Provider, bool) {
	i := strings.Index(secretRef, "://")
	if i <= 0 {
		return nil, false
	}
	return r.ForScheme(secretRef[:i])
}

// Providers returns a snapshot of every registered provider, in
// unspecified order. Used by the boot-time wiring to validate tokens for
// the providers actually in use.
func (r *Registry) Providers() []Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Provider, 0, len(r.byScheme))
	for _, p := range r.byScheme {
		out = append(out, p)
	}
	return out
}

// defaultRegistry is the process-wide registry that side-effect imports
// (e.g., internal/credstore/onepassword) populate from init(). Tests that
// want isolation should construct their own Registry via NewRegistry.
var defaultRegistry = NewRegistry()

// Default returns the process-wide registry that side-effect imports populate
// from init(). The binary's main package passes it explicitly into the
// command wiring so the server's provider set is an explicit dependency
// rather than an implicit consequence of import order; tests pass their own
// Registry from NewRegistry for isolation.
func Default() *Registry { return defaultRegistry }

// Register adds p to the process-wide default Registry. See Registry.Register
// for panic conditions.
func Register(p Provider) { defaultRegistry.Register(p) }

// ForScheme returns the Provider registered under scheme in the default
// Registry.
func ForScheme(scheme string) (Provider, bool) { return defaultRegistry.ForScheme(scheme) }

// ForName returns the Provider registered under name in the default Registry.
func ForName(name string) (Provider, bool) { return defaultRegistry.ForName(name) }

// ForSecretRef looks up the Provider for secretRef in the default Registry.
func ForSecretRef(secretRef string) (Provider, bool) {
	return defaultRegistry.ForSecretRef(secretRef)
}

// Providers returns every Provider registered in the default Registry.
func Providers() []Provider { return defaultRegistry.Providers() }
