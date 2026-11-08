// Package keychain implements a credstore.Provider backed by the OS secret
// store: the macOS Keychain, or a Secret Service (such as GNOME Keyring) on
// Linux. A keychain://<item> reference resolves to the value `postern secret
// set` stored under that item. The user's desktop session unlocks the store,
// so the provider needs no service-account token.
package keychain

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/99designs/keyring"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/credstore"
)

const (
	providerName   = "keychain"
	providerScheme = "keychain"
	// serviceName is the macOS Keychain service postern's items live under.
	serviceName = "postern"
	// keyPrefix namespaces postern's items in stores shared with other
	// applications, such as the Secret Service login collection, and keeps
	// them apart from the service-account token entries.
	keyPrefix = "postern/"
)

// ErrNoBackend reports that no native OS secret store could be opened.
var ErrNoBackend = errors.New("no OS secret store available " +
	"(needs the macOS Keychain or a Secret Service such as GNOME Keyring)")

// Provider implements credstore.Provider over the OS secret store. open is
// the store opener: keyring.Open in production, a fake in tests.
type Provider struct {
	open func(keyring.Config) (keyring.Keyring, error)
}

// NewProvider constructs a Provider that opens the real OS secret store.
func NewProvider() *Provider { return &Provider{open: keyring.Open} }

// Name returns the registry-facing provider name.
func (p *Provider) Name() string { return providerName }

// Scheme returns the secret-reference URI scheme keychain refs use.
func (p *Provider) Scheme() string { return providerScheme }

// ShouldCache reports that every keychain value may be cached: items hold
// static API keys, not rotating values.
func (p *Provider) ShouldCache(_ string) bool { return true }

// Tokenless marks the provider as needing no service-account token.
func (p *Provider) Tokenless() {}

// ValidateSettings rejects any non-empty settings map: the provider has no
// per-credstore settings, so a `settings:` block is a mistake.
func (p *Provider) ValidateSettings(settings map[string]string) error {
	if len(settings) > 0 {
		return fmt.Errorf("provider %s: settings not supported (recognizes no keys)", providerName)
	}
	return nil
}

// Validate opens the store and reads a key no item can have, proving the
// store answers without touching a stored value. A host with no native store
// fails the proxy closed at boot; a store that does not answer before ctx ends
// fails the check. token is ignored.
func (p *Provider) Validate(ctx context.Context, _ string, settings map[string]string) error {
	if err := p.ValidateSettings(settings); err != nil {
		return err
	}
	ring, err := p.openStore()
	if err != nil {
		return err
	}
	_, err = read(ctx, func() (keyring.Item, error) { return ring.Get(keyPrefix) })
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return fmt.Errorf("keychain: read OS secret store: %w", err)
	}
	return nil
}

// NewResolver returns a broker.Resolver reading from the OS secret store.
// token is ignored.
func (p *Provider) NewResolver(_ context.Context, _ string, settings map[string]string) (broker.Resolver, error) {
	if err := p.ValidateSettings(settings); err != nil {
		return nil, err
	}
	ring, err := p.openStore()
	if err != nil {
		return nil, err
	}
	return newResolver(ring), nil
}

// SetSecret stores value under the item a keychain://<item> reference names,
// replacing any existing value.
func (p *Provider) SetSecret(_ context.Context, ref, value string) error {
	name, err := itemName(ref)
	if err != nil {
		return err
	}
	if value == "" {
		return errors.New("keychain: value is empty")
	}
	ring, err := p.openStore()
	if err != nil {
		return err
	}
	return ring.Set(keyring.Item{Key: keyPrefix + name, Data: []byte(value), Label: "postern: " + name})
}

// RemoveSecret deletes the item a keychain://<item> reference names. A
// missing item is not an error.
func (p *Provider) RemoveSecret(_ context.Context, ref string) error {
	name, err := itemName(ref)
	if err != nil {
		return err
	}
	ring, err := p.openStore()
	if err != nil {
		return err
	}
	err = ring.Remove(keyPrefix + name)
	if errors.Is(err, keyring.ErrKeyNotFound) {
		return nil
	}
	return err
}

// openStore opens the first native OS secret store available. The library's
// file, pass, and keyctl fallbacks are excluded: they are not the OS store,
// and the file backend would prompt for a password of its own. Its kwallet
// backend is excluded too: it would open a separate wallet named after
// ServiceName and ignores the status writeEntry returns, so a rejected write
// would look stored. KWallet is reachable when it serves the Secret Service API.
func (p *Provider) openStore() (keyring.Keyring, error) {
	ring, err := p.open(keyring.Config{
		ServiceName: serviceName,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,
			keyring.SecretServiceBackend,
		},
		// The login collection unlocks with the desktop session; the library
		// default creates a collection with its own password that stays locked.
		LibSecretCollectionName: "login",
		// Lets the binary that wrote an item read it back without a prompt.
		KeychainTrustApplication: true,
	})
	// keyring.Open reports every failure, including a backend that would not
	// open, as ErrNoAvailImpl.
	if err != nil {
		return nil, ErrNoBackend
	}
	return ring, nil
}

// itemName extracts the item from a keychain://<item> reference, accepting
// the credstore-qualified keychain+<name>://<item> form.
func itemName(ref string) (string, error) {
	name, ok := strings.CutPrefix(credstore.StripQualifier(ref), providerScheme+"://")
	if !ok || name == "" {
		return "", fmt.Errorf("keychain: reference %q is not keychain://<item>", ref)
	}
	return name, nil
}

// init registers the provider in the process-wide credstore registry.
func init() {
	credstore.Register(NewProvider())
}
