package onepassword

import (
	"context"
	"errors"
	"testing"

	sdk "github.com/1password/onepassword-sdk-go"
)

// fakeVaults satisfies the package's vaultsLister consumer interface. Only
// List is exercised by Client today; future operations get their own narrow
// interfaces and fakes rather than expanding this one.
type fakeVaults struct {
	listErr error
	calls   int
	last    []sdk.VaultListParams
}

func (f *fakeVaults) List(_ context.Context, params ...sdk.VaultListParams) ([]sdk.VaultOverview, error) {
	f.calls++
	f.last = params
	if f.listErr != nil {
		return nil, f.listErr
	}
	return []sdk.VaultOverview{{ID: "vault-id", Title: "vault"}}, nil
}

func TestHealthCheckSuccess(t *testing.T) {
	t.Parallel()

	fv := &fakeVaults{}
	c := &Client{vaults: fv}

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck = %v, want nil", err)
	}
	if fv.calls != 1 {
		t.Fatalf("vaults.List called %d times, want 1", fv.calls)
	}
}

func TestHealthCheckTreatsEmptyVaultListAsSuccess(t *testing.T) {
	t.Parallel()

	// A service account may have zero vaults granted and still be valid;
	// HealthCheck must not conflate empty list with an authentication
	// failure. Implementation guarantees this by only inspecting err.
	fv := &fakeVaults{}
	fv.listErr = nil
	c := &Client{vaults: emptyVaults{}}

	if err := c.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck on empty vaults = %v, want nil", err)
	}
}

type emptyVaults struct{}

func (emptyVaults) List(context.Context, ...sdk.VaultListParams) ([]sdk.VaultOverview, error) {
	return nil, nil
}

func TestHealthCheckPropagatesError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("invalid service account token")
	fv := &fakeVaults{listErr: sentinel}
	c := &Client{vaults: fv}

	err := c.HealthCheck(context.Background())
	if err == nil {
		t.Fatalf("HealthCheck returned nil, want error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("HealthCheck error = %v, want wrap of %v", err, sentinel)
	}
}

func TestNewRejectsEmptyToken(t *testing.T) {
	t.Parallel()

	// The SDK rejects an empty token at NewClient time; we surface that as
	// the construction error rather than deferring to the first call. This
	// pins our reliance on the SDK's validate-before-handshake behaviour.
	if _, err := New(context.Background(), "", "test"); err == nil {
		t.Fatalf("New(empty token) returned nil error, want failure")
	}
}
