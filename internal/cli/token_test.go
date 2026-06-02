package cli_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/token"
)

// fakeValidator returns whatever err it's configured with and records every
// token it was asked to validate so tests can assert call shape.
type fakeValidator struct {
	err    error
	calls  int
	tokens []string
}

func (v *fakeValidator) Validate(_ context.Context, tok string) error {
	v.calls++
	v.tokens = append(v.tokens, tok)
	return v.err
}

const testAccount = "default"

const fixtureToken = "ops_eyJhbGciOiJFUzI1NiJ9.PAYLOAD.a3F2"

func runTokenCmd(t *testing.T, args []string, stdin string, store token.Store, v cli.Validator) (string, string, error) {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := cli.NewTokenCmd(store, v, testAccount)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)

	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestTokenSetStdinHappyPath(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	v := &fakeValidator{}

	stdout, _, err := runTokenCmd(t, []string{"set", "--stdin"}, fixtureToken+"\n", store, v)
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if v.calls != 1 {
		t.Fatalf("validator called %d times, want 1", v.calls)
	}
	if v.tokens[0] != fixtureToken {
		t.Fatalf("validator got token %q, want %q (trailing newline must be trimmed)", v.tokens[0], fixtureToken)
	}

	got, err := store.Get(context.Background(), testAccount)
	if err != nil {
		t.Fatalf("post-set Get: %v", err)
	}
	if got != fixtureToken {
		t.Fatalf("stored %q, want %q", got, fixtureToken)
	}
	if !strings.Contains(stdout, "Stored in") {
		t.Errorf("stdout missing success line: %q", stdout)
	}
	if !strings.Contains(stdout, "Fingerprint:") {
		t.Errorf("stdout missing fingerprint line: %q", stdout)
	}
	if strings.Contains(stdout, fixtureToken) {
		t.Fatalf("CRITICAL: stdout leaked the full token: %q", stdout)
	}
}

func TestTokenSetFromEnv(t *testing.T) {
	// No t.Parallel — t.Setenv requires a serial test.
	t.Setenv("POSTERN_TEST_TOKEN", fixtureToken)

	store := token.NewMemoryStore()
	v := &fakeValidator{}

	_, _, err := runTokenCmd(t, []string{"set", "--from-env", "POSTERN_TEST_TOKEN"}, "", store, v)
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := store.Get(context.Background(), testAccount)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != fixtureToken {
		t.Fatalf("stored %q, want %q", got, fixtureToken)
	}
}

func TestTokenSetFromEnvMissingVar(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	v := &fakeValidator{}

	_, _, err := runTokenCmd(t, []string{"set", "--from-env", "POSTERN_NONEXISTENT_VAR_XYZ"}, "", store, v)
	if err == nil {
		t.Fatalf("set with missing env var returned nil error")
	}
	if v.calls != 0 {
		t.Errorf("validator called %d times before env check, want 0", v.calls)
	}
}

func TestTokenSetValidateBeforeStore(t *testing.T) {
	t.Parallel()

	// CRITICAL invariant: a failing validator must not leave anything in
	// the store. This is the fail-closed guarantee.
	store := token.NewMemoryStore()
	v := &fakeValidator{err: errors.New("invalid token")}

	_, stderr, err := runTokenCmd(t, []string{"set", "--stdin"}, fixtureToken, store, v)
	if err == nil {
		t.Fatalf("set returned nil error despite validator failure")
	}
	if !strings.Contains(err.Error(), "validate") {
		t.Errorf("error %q should mention validation failure", err.Error())
	}

	_, getErr := store.Get(context.Background(), testAccount)
	if !errors.Is(getErr, token.ErrNotFound) {
		t.Fatalf("after failed validate, store contains token (Get err = %v); validate-before-store violated", getErr)
	}

	if strings.Contains(stderr, fixtureToken) {
		t.Fatalf("CRITICAL: stderr leaked the full token: %q", stderr)
	}
}

func TestTokenSetRequiresSource(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	v := &fakeValidator{}

	_, _, err := runTokenCmd(t, []string{"set"}, "", store, v)
	if err == nil {
		t.Fatalf("set with no source flag returned nil")
	}
}

func TestTokenStatusEmpty(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	v := &fakeValidator{}

	_, _, err := runTokenCmd(t, []string{"status"}, "", store, v)
	if err == nil {
		t.Fatalf("status on empty store returned nil; expected error")
	}
}

func TestTokenStatusPopulated(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	if err := store.Set(context.Background(), testAccount, fixtureToken); err != nil {
		t.Fatalf("pre-Set: %v", err)
	}

	stdout, _, err := runTokenCmd(t, []string{"status"}, "", store, &fakeValidator{})
	if err != nil {
		t.Fatalf("status: %v", err)
	}

	for _, want := range []string{"backend:", "account:", "fingerprint:", "memory", testAccount, "ops_…a3F2"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status output missing %q in: %q", want, stdout)
		}
	}
	if strings.Contains(stdout, fixtureToken) {
		t.Fatalf("CRITICAL: status leaked the full token: %q", stdout)
	}
}

func TestTokenTestValid(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	if err := store.Set(context.Background(), testAccount, fixtureToken); err != nil {
		t.Fatalf("pre-Set: %v", err)
	}
	v := &fakeValidator{}

	stdout, _, err := runTokenCmd(t, []string{"test"}, "", store, v)
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	if v.calls != 1 || v.tokens[0] != fixtureToken {
		t.Fatalf("validator calls = %d tokens = %v", v.calls, v.tokens)
	}
	if !strings.Contains(stdout, "valid") {
		t.Errorf("stdout missing 'valid': %q", stdout)
	}
}

func TestTokenTestInvalid(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	if err := store.Set(context.Background(), testAccount, fixtureToken); err != nil {
		t.Fatalf("pre-Set: %v", err)
	}
	v := &fakeValidator{err: errors.New("revoked")}

	_, _, err := runTokenCmd(t, []string{"test"}, "", store, v)
	if err == nil {
		t.Fatalf("test with revoked token returned nil")
	}
}

func TestTokenTestEmpty(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	v := &fakeValidator{}

	_, _, err := runTokenCmd(t, []string{"test"}, "", store, v)
	if err == nil {
		t.Fatalf("test on empty store returned nil")
	}
	if v.calls != 0 {
		t.Errorf("validator called %d times with empty store, want 0", v.calls)
	}
}

func TestTokenRm(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	if err := store.Set(context.Background(), testAccount, fixtureToken); err != nil {
		t.Fatalf("pre-Set: %v", err)
	}

	stdout, _, err := runTokenCmd(t, []string{"rm"}, "", store, &fakeValidator{})
	if err != nil {
		t.Fatalf("rm: %v", err)
	}
	if !strings.Contains(stdout, "Removed") {
		t.Errorf("stdout missing 'Removed': %q", stdout)
	}

	if _, getErr := store.Get(context.Background(), testAccount); !errors.Is(getErr, token.ErrNotFound) {
		t.Fatalf("after rm, store still has token (err = %v)", getErr)
	}
}

func TestTokenRmIdempotent(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()

	// Removing a non-existent entry must succeed silently — running the
	// same `postern token rm` twice cannot blow up.
	if _, _, err := runTokenCmd(t, []string{"rm"}, "", store, &fakeValidator{}); err != nil {
		t.Fatalf("rm on empty store: %v", err)
	}
}
