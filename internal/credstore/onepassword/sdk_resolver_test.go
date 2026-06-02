package onepassword

import (
	"context"
	"errors"
	"testing"
)

// fakeSecrets satisfies the package's secretsResolver consumer interface
// without dragging in the real SDK.
type fakeSecrets struct {
	value   string
	err     error
	lastRef string
	calls   int
}

func (f *fakeSecrets) Resolve(_ context.Context, secretReference string) (string, error) {
	f.calls++
	f.lastRef = secretReference
	if f.err != nil {
		return "", f.err
	}
	return f.value, nil
}

func TestSDKResolver_PassesReferenceThroughAndReturnsValue(t *testing.T) {
	t.Parallel()

	fs := &fakeSecrets{value: "sk-real"}
	r := &sdkResolver{secrets: fs}

	got, err := r.Resolve(context.Background(), "", "op://Agents/Anthropic/api_key")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "sk-real" {
		t.Fatalf("Resolve = %q, want %q", got, "sk-real")
	}
	if fs.lastRef != "op://Agents/Anthropic/api_key" {
		t.Fatalf("lastRef = %q, want %q", fs.lastRef, "op://Agents/Anthropic/api_key")
	}
}

func TestSDKResolver_WrapsSDKError(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("vault not found")
	fs := &fakeSecrets{err: sentinel}
	r := &sdkResolver{secrets: fs}

	_, err := r.Resolve(context.Background(), "", "op://V/I/f")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrap of %v", err, sentinel)
	}
}

// vaultID is reserved for future multi-vault routing. Passing a non-empty
// value today is a programming error; fail closed rather than silently
// ignore.
func TestSDKResolver_RejectsNonEmptyVaultID(t *testing.T) {
	t.Parallel()

	fs := &fakeSecrets{value: "sk-real"}
	r := &sdkResolver{secrets: fs}

	_, err := r.Resolve(context.Background(), "vault-a", "op://V/I/f")
	if err == nil {
		t.Fatalf("Resolve with non-empty vaultID: want error (multi-vault not implemented), got nil")
	}
	if fs.calls != 0 {
		t.Fatalf("inner SDK called %d times despite invalid vaultID, want 0", fs.calls)
	}
}
