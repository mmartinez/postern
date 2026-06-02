// Package credstore defines the plug-in seam for credential vendors.
//
// A Provider implements the contract between Postern's broker runtime and a
// specific credential vendor. Providers register themselves at init time
// via a process-wide Registry keyed by the secret-reference URI scheme
// they accept (op, bw, vault, ...). The broker path consults the registry
// once per rule at boot to construct a Resolver; adding a new vendor is a
// single new sub-package with an init() call and no edits to broker or
// proxy code.
package credstore

import (
	"context"

	"github.com/mmartinez/postern/internal/broker"
)

// Provider is the contract every credential vendor implements. Methods are
// expected to be safe for concurrent use; Name and Scheme must be stable
// for the lifetime of the process.
type Provider interface {
	// Name is the human-readable provider identifier surfaced in config
	// (e.g., provider: op) and in logs.
	Name() string
	// Scheme is the secret-reference URI prefix (without the "://") this
	// provider claims. Must be lowercase, non-empty, and unique within a
	// Registry.
	Scheme() string
	// Validate performs a cheap, read-only sanity ping against the vendor
	// using token. It runs once at boot before any request is brokered;
	// failures fail the proxy closed rather than wait for the first
	// request to surface a bad credential. settings is the credstore's
	// provider-interpreted config map (e.g. a self-hosted server URL);
	// providers that recognize no keys ignore it at runtime.
	Validate(ctx context.Context, token string, settings map[string]string) error
	// ValidateSettings checks the credstore's provider-interpreted settings
	// map offline, without a token or any network call. The `config
	// validate` path calls it so an unknown key or a malformed value is a
	// line-numbered error rather than a silently ignored field or a boot
	// failure. A provider that recognizes no keys returns an error for any
	// non-empty map and nil for an empty/absent one.
	ValidateSettings(settings map[string]string) error
	// ShouldCache reports whether a resolved value for secretRef may be
	// served from the broker cache. Vendors return false for references
	// whose value is inherently short-lived (e.g. a one-time password) so
	// the cache layer re-resolves them on every request. The vendor owns
	// this decision because the non-cacheable-ref grammar (such as the op
	// scheme's "?attribute=otp" suffix) is vendor-specific; the cache
	// itself stays vendor-agnostic.
	ShouldCache(secretRef string) bool
	// NewResolver constructs a broker.Resolver authenticated with token.
	// settings is consumed transiently (parsed and bound into the returned
	// resolver) and never stored on the Provider, which is a process-wide
	// singleton. The caller is responsible for wrapping the result in any
	// cache or metrics decorators before handing it to broker.Hook.
	NewResolver(ctx context.Context, token string, settings map[string]string) (broker.Resolver, error)
}
