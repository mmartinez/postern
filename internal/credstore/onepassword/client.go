// Package onepassword wraps the official 1Password Go SDK so the rest of
// Postern can construct, validate, and resolve secrets without importing
// the SDK directly. The wrapper isolates the pre-1.0 SDK behind a small
// surface that's easy to fake in tests: Client construction from a
// service-account token, HealthCheck, and a broker.Resolver backed by
// SecretsAPI.Resolve.
package onepassword

import (
	"context"
	"fmt"

	sdk "github.com/1password/onepassword-sdk-go"

	"github.com/mmartinez/postern/internal/broker"
)

// integrationName is sent to 1Password's audit log when this binary calls
// the SDK. It must match the integration name registered with 1Password.
const integrationName = "Postern"

// vaultsLister is the narrow slice of sdk.VaultsAPI HealthCheck depends on.
// Keeping the interface in the consumer package (rather than relying on the
// full VaultsAPI) means test fakes only have to implement the one method we
// actually call.
type vaultsLister interface {
	List(ctx context.Context, params ...sdk.VaultListParams) ([]sdk.VaultOverview, error)
}

// secretsResolver is the narrow slice of sdk.SecretsAPI sdkResolver uses.
// Kept here so test fakes only need to implement Resolve, and so the SDK's
// ResolveAll surface doesn't leak into the broker code path.
type secretsResolver interface {
	Resolve(ctx context.Context, secretReference string) (string, error)
}

// Client is the narrow surface other postern packages depend on. It is
// constructed from a service-account token and exposes the minimum set of
// operations the broker runtime needs.
type Client struct {
	vaults  vaultsLister
	secrets secretsResolver
}

// New constructs a Client backed by a fresh SDK client authenticated with
// the given service-account token. integrationVersion is sent to 1Password
// as part of the integration metadata (typically internal/version.Version).
func New(ctx context.Context, token, integrationVersion string) (*Client, error) {
	s, err := sdk.NewClient(
		ctx,
		sdk.WithServiceAccountToken(token),
		sdk.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("1password client: %w", err)
	}
	return &Client{vaults: s.Vaults(), secrets: s.Secrets()}, nil
}

// Resolver returns a broker.Resolver backed by this Client's SDK secrets
// handle. Callers wrap the result with credstore.NewCachedResolver before
// passing it to the broker so TTL and non-cacheable-ref semantics are
// uniform across vendors.
func (c *Client) Resolver() broker.Resolver {
	return &sdkResolver{secrets: c.secrets}
}

// HealthCheck verifies the configured service-account token is valid and
// the 1Password SaaS is reachable. It calls Vaults.List — a cheap, read-only
// operation — and returns nil on success or the wrapped SDK error on failure.
//
// The empty-list case is treated as success: a service account may have
// zero vaults granted to it and still be a valid token.
func (c *Client) HealthCheck(ctx context.Context) error {
	if _, err := c.vaults.List(ctx); err != nil {
		return fmt.Errorf("1password health check: %w", err)
	}
	return nil
}
