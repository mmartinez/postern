//go:build keyring

// Package-level integration test exercising a real OS keyring backend via
// 99designs/keyring. Gated behind the "keyring" build tag so the default
// `go test ./...` run on a developer machine — or in the devcontainer where
// no Secret Service daemon is reachable — never touches the host keychain.
//
// The CI job token-keyring-e2e (see .github/workflows/ci.yml) runs this test
// under `dbus-run-session` with a freshly started `gnome-keyring-daemon`,
// providing a real Secret Service implementation for the lifecycle assertions.

package token_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	keyringlib "github.com/99designs/keyring"

	"github.com/mmartinez/postern/internal/token"
)

func TestSecretServiceLifecycle(t *testing.T) {
	// No t.Parallel — this test mutates real OS state and must run serially
	// in case another test in this package starts using the keyring too.

	// Skip if no D-Bus session is reachable. CI always sets this via
	// dbus-run-session; developer machines without a desktop session
	// won't have it.
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Skip("DBUS_SESSION_BUS_ADDRESS not set; skipping (no Secret Service backend reachable)")
	}

	available := keyringlib.AvailableBackends()
	hasSecretService := false
	for _, b := range available {
		if b == keyringlib.SecretServiceBackend {
			hasSecretService = true
			break
		}
	}
	if !hasSecretService {
		t.Skipf("secret-service backend not in AvailableBackends() = %v; skipping", available)
	}

	const (
		// Use a recognizable service name so a failed test leaves a
		// scrubable entry behind. The test cleans up in the happy path
		// but a crash could leave residue.
		serviceName = "postern-t2-5-integration"
		account     = "ci-test-account"
		secret      = "ops_eyJhbGciOiJFUzI1NiJ9.PAYLOAD.a3F2" //nolint:gosec // synthetic fixture, not a credential
	)

	ring, err := keyringlib.Open(keyringlib.Config{
		ServiceName:     serviceName,
		AllowedBackends: []keyringlib.BackendType{keyringlib.SecretServiceBackend},
	})
	if err != nil {
		t.Fatalf("keyring.Open(secret-service): %v", err)
	}
	s := token.NewKeyringStore(ring, string(keyringlib.SecretServiceBackend))

	ctx := context.Background()

	t.Cleanup(func() {
		// Best-effort cleanup; ignore the "already gone" case.
		_ = s.Delete(ctx, account)
	})

	if err := s.Set(ctx, account, secret); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Independently verify the entry made it into the real Secret Service
	// store via the libsecret CLI (installed by the CI job alongside
	// gnome-keyring). secret-tool's exit code is 0 when the entry exists.
	if _, err := exec.LookPath("secret-tool"); err == nil {
		out, secretToolErr := exec.Command(
			"secret-tool", "lookup",
			"service", serviceName,
			"username", account,
		).Output()
		if secretToolErr != nil {
			t.Fatalf("secret-tool lookup: %v", secretToolErr)
		}
		if strings.TrimSpace(string(out)) != secret {
			t.Fatalf("secret-tool returned mismatched value (length only logged): got %d bytes, want %d",
				len(strings.TrimSpace(string(out))), len(secret))
		}
	} else {
		t.Log("secret-tool not installed; skipping cross-check")
	}

	got, err := s.Get(ctx, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != secret {
		t.Fatalf("Get returned %d bytes, want %d", len(got), len(secret))
	}

	if err := s.Delete(ctx, account); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = s.Get(ctx, account)
	if !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("post-Delete Get err = %v, want ErrNotFound", err)
	}
}
