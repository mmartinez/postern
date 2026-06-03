package onepassword

import (
	"context"
	"fmt"
)

// sdkResolver adapts the 1Password Go SDK's secrets API to broker.Resolver.
// It is constructed via Client.Resolver(); tests in this package construct
// it directly with a secretsResolver fake.
//
// keepAlive pins the owning *Client (and through it the *sdk.Client) for the
// resolver's lifetime. The broker keeps the resolver alive for the whole
// process, so this transitively keeps the SDK client reachable and prevents
// its GC finalizer from calling ReleaseClient out from under the secrets
// handle. Without it, a resolve after the client is finalized fails with
// "invalid client id". It is nil in unit tests that exercise Resolve directly.
type sdkResolver struct {
	secrets   secretsResolver
	keepAlive *Client
}

// Resolve delegates to the SDK with the secret reference unchanged. The
// vault is encoded in the reference URI (op://<vault>/<item>/<field>),
// so vaultID is reserved for future multi-vault routing and must currently
// be empty. Passing a non-empty vaultID is treated as a programming error
// and fails closed without contacting the SDK, so a misconfigured caller
// cannot accidentally resolve the wrong secret.
func (r *sdkResolver) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	if vaultID != "" {
		return "", fmt.Errorf("vaultID-scoped resolution is not implemented (vaultID=%q)", vaultID)
	}
	v, err := r.secrets.Resolve(ctx, secretRef)
	if err != nil {
		return "", fmt.Errorf("sdk resolve: %w", err)
	}
	return v, nil
}
