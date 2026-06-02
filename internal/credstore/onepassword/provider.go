package onepassword

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/version"
)

// providerName is the human-readable identifier the credstore registry
// surfaces in config and logs. It is intentionally lowercase and brand-
// neutral in the source line that registers it so banned-strings gating
// elsewhere in the tree does not need to be revisited.
const (
	providerName   = "1password"
	providerScheme = "op"
)

// Provider implements credstore.Provider for the 1Password Service
// Account vendor. It carries integrationVersion (sent to the vendor's
// audit log) but is otherwise stateless; tokens come in per call so the
// same Provider can validate or resolve for different callers.
type Provider struct {
	integrationVersion string
}

// NewProvider constructs a Provider that tags vendor audit-log entries
// with integrationVersion. Pass internal/version.Version in production;
// tests can pass any non-empty string.
func NewProvider(integrationVersion string) *Provider {
	return &Provider{integrationVersion: integrationVersion}
}

// Name returns the registry-facing provider name.
func (p *Provider) Name() string { return providerName }

// Scheme returns the secret-reference URI scheme this provider claims.
func (p *Provider) Scheme() string { return providerScheme }

// ShouldCache reports whether a resolved value for secretRef may be cached.
// Every 1Password reference is cacheable except a one-time password, whose
// value rotates every 30s; bypassing the cache for OTP refs is an invariant,
// not an optimization.
func (p *Provider) ShouldCache(secretRef string) bool {
	return !isOneTimePassword(secretRef)
}

// isOneTimePassword reports whether secretRef selects a one-time password via
// its query string. The 1Password grammar selects an OTP with
// "?attribute=otp" (alias "totp"). Matching is done by parsing the query —
// not a string suffix — so an extra or reordered parameter
// ("?attribute=otp&label=x") is still recognised and never cached. A query
// that fails to parse is treated as an OTP (non-cacheable) so an unparseable
// ref errs on the side of always re-resolving rather than caching a rotating
// value.
func isOneTimePassword(secretRef string) bool {
	i := strings.IndexByte(secretRef, '?')
	if i < 0 {
		return false
	}
	q, err := url.ParseQuery(secretRef[i+1:])
	if err != nil {
		return true
	}
	switch q.Get("attribute") {
	case "otp", "totp":
		return true
	default:
		return false
	}
}

// Validate pings the vendor with token to confirm the credential is live
// and the SaaS is reachable. It constructs a transient client so a bad
// token never produces a long-lived handle. settings is ignored:
// 1Password recognizes no per-credstore settings keys (ValidateSettings
// rejects a non-empty map at config-validate time).
func (p *Provider) Validate(ctx context.Context, token string, _ map[string]string) error {
	c, err := New(ctx, token, p.integrationVersion)
	if err != nil {
		return fmt.Errorf("provider validate: %w", err)
	}
	return c.HealthCheck(ctx)
}

// ValidateSettings rejects any non-empty settings map: 1Password is
// configured entirely by its token, so a `settings:` block on an op
// credstore is a mistake (likely meant for a different provider) and must
// be surfaced rather than silently ignored.
func (p *Provider) ValidateSettings(settings map[string]string) error {
	if len(settings) > 0 {
		return fmt.Errorf("provider %s: settings not supported (recognizes no keys)", providerName)
	}
	return nil
}

// NewResolver returns a broker.Resolver authenticated with token. The
// caller wraps this in a cache (and other decorators) before handing it
// to broker.Hook. settings is ignored (see Validate).
func (p *Provider) NewResolver(ctx context.Context, token string, _ map[string]string) (broker.Resolver, error) {
	c, err := New(ctx, token, p.integrationVersion)
	if err != nil {
		return nil, fmt.Errorf("provider new resolver: %w", err)
	}
	return c.Resolver(), nil
}

// init wires this provider into the process-wide credstore registry. The
// side-effect-import pattern mirrors database/sql/driver: any binary that
// imports this package gets the provider registered automatically.
func init() {
	credstore.Register(NewProvider(version.Version))
}
