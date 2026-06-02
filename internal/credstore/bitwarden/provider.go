package bitwarden

import (
	"context"
	"fmt"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"
)

const (
	providerName   = "bitwarden"
	providerScheme = "bw"
)

// Provider implements credstore.Provider backed by the bws CLI. It is a
// stateless process-wide singleton: the per-credstore token and settings
// arrive on each call and are consumed transiently (bound into the returned
// resolver or used for a one-shot validate), never stored on the Provider.
type Provider struct{}

// NewProvider constructs a Provider.
func NewProvider() *Provider { return &Provider{} }

// Name returns the registry-facing provider name.
func (p *Provider) Name() string { return providerName }

// Scheme returns the secret-reference URI scheme bitwarden refs use.
func (p *Provider) Scheme() string { return providerScheme }

// ShouldCache reports whether a resolved value for secretRef may be cached.
// Secrets Manager has no one-time-password / rotating-ref grammar, so every
// bw:// value is cacheable. This is a semantic assumption (this provider
// resolves only UUID refs, and SM has no rotating-secret concept); revisit it
// if name/project refs or rotating secrets are ever supported, since unlike op
// there is no grammar signal to key on.
func (p *Provider) ShouldCache(_ string) bool { return true }

// ValidateSettings checks the provider-interpreted settings offline, rejecting
// unknown keys and a malformed server_url with no token or network call so a
// typo surfaces at `config validate` time rather than at boot.
func (p *Provider) ValidateSettings(settings map[string]string) error {
	_, err := parseSettings(settings)
	return err
}

// Validate pings Secrets Manager with token via `bws secret list`, the cheapest
// read-only tokenful call; an empty list still means a valid token. A bad token
// (non-zero exit) or a missing bws binary fails the proxy closed at boot rather
// than waiting for the first request to surface it.
func (p *Provider) Validate(ctx context.Context, token string, settings map[string]string) error {
	s, err := parseSettings(settings)
	if err != nil {
		return err
	}
	run, err := newExecRunner(s.bwsPath)
	if err != nil {
		return err
	}
	args := []string{"secret", "list", "--output", "json"}
	if s.serverURL != "" {
		args = append(args, "--server-url", s.serverURL)
	}
	if _, err := run.run(ctx, args, bwsEnv(token)); err != nil {
		return fmt.Errorf("bitwarden validate: %w", err)
	}
	return nil
}

// NewResolver returns a broker.Resolver bound to token and settings. settings
// is consumed here (parsed, bws path resolved, both bound into the returned
// resolver) and never stored on the singleton. ctx is unused: the bws binary is
// resolved synchronously and no network call happens until the first Resolve.
func (p *Provider) NewResolver(_ context.Context, token string, settings map[string]string) (broker.Resolver, error) {
	s, err := parseSettings(settings)
	if err != nil {
		return nil, err
	}
	run, err := newExecRunner(s.bwsPath)
	if err != nil {
		return nil, err
	}
	return &bwsResolver{runner: run, token: token, serverURL: s.serverURL}, nil
}

// init wires this provider into the process-wide credstore registry via the
// side-effect-import pattern (mirrors database/sql/driver). With the former
// build tag removed it now registers in the default binary.
func init() {
	credstore.Register(NewProvider())
}
