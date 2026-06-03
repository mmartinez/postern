package onepassword

import (
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"

	sdk "github.com/1password/onepassword-sdk-go"

	"github.com/mmartinez/postern/internal/broker"
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

// TestResolverKeepsSDKClientReachable is the regression guard for the
// intermittent "invalid client id" production failure. The 1Password SDK
// attaches a GC finalizer to *sdk.Client that calls ReleaseClient, freeing the
// underlying core client; the Secrets()/Vaults() handles do not keep that
// parent client reachable. Once Postern held only those handles, the GC could
// finalize the client under load and every later resolve failed with
// "invalid client id" until restart. The resolver returned by Resolver() must
// pin the client for its whole lifetime so the finalizer never fires.
func TestResolverKeepsSDKClientReachable(t *testing.T) {
	// Not parallel: drives runtime.GC and inspects finalizer scheduling.
	var finalized int32

	// Build the client and resolver inside a closure so the *sdk.Client and the
	// *Client locals go out of scope when it returns. Only the resolver escapes
	// — exactly the shape the broker keeps after New/Resolver return. If the
	// resolver retains the client it stays reachable; if not, it becomes
	// unreachable here and the finalizer is free to run.
	r := func() broker.Resolver {
		s := &sdk.Client{}
		runtime.SetFinalizer(s, func(*sdk.Client) { atomic.StoreInt32(&finalized, 1) })
		c := &Client{sdk: s, secrets: &fakeSecrets{value: "sk"}}
		return c.Resolver()
	}()

	// A few GC cycles, yielding to the finalizer goroutine between them, give an
	// eligible finalizer ample opportunity to run.
	for i := 0; i < 10 && atomic.LoadInt32(&finalized) == 0; i++ {
		runtime.GC()
		runtime.Gosched()
	}

	if atomic.LoadInt32(&finalized) != 0 {
		t.Fatal(`sdk client was finalized while the resolver was still live: resolves would fail with "invalid client id"`)
	}

	// The resolver must outlive the GC loop above for the assertion to mean
	// anything; resolving through it here keeps it reachable and confirms the
	// retained handle still works.
	if _, err := r.Resolve(context.Background(), "", "op://V/I/f"); err != nil {
		t.Fatalf("Resolve after GC: %v", err)
	}
	runtime.KeepAlive(r)
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
