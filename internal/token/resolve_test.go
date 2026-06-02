package token_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/token"
)

func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func TestResolve_AutoChainPrefersFileThenEnvThenKeychain(t *testing.T) {
	// Not parallel — t.Setenv mutates process state.

	filePath := writeTokenFile(t, "from-file\n") // trailing newline must be trimmed
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN_TEST", "from-env")

	store := token.NewMemoryStore()
	_ = store.Set(context.Background(), "default", "from-keychain")

	cases := []struct {
		name       string
		file       string
		envVar     string
		keychain   string
		wantToken  string
		wantSource string
	}{
		{"file wins", filePath, "OP_SERVICE_ACCOUNT_TOKEN_TEST", "default", "from-file", "file"},
		{"env when no file", "", "OP_SERVICE_ACCOUNT_TOKEN_TEST", "default", "from-env", "env"},
		{"keychain when no file or env", "", "OP_SERVICE_ACCOUNT_TOKEN_TEST_UNSET", "default", "from-keychain", "keychain"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Token{
				Source:          config.TokenSourceAuto,
				File:            tc.file,
				EnvVar:          tc.envVar,
				KeychainAccount: tc.keychain,
			}
			got, src, err := token.Resolve(context.Background(), cfg, store)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tc.wantToken {
				t.Fatalf("token = %q, want %q", got, tc.wantToken)
			}
			if src != tc.wantSource {
				t.Fatalf("source = %q, want %q", src, tc.wantSource)
			}
		})
	}
}

// In auto mode a configured-but-missing file is one option among several, so
// a nonexistent path must fall through to env/keychain rather than abort the
// chain. Contrast TestResolve_ExplicitSourceMissingReturnsError, where a
// pinned source:file is expected to fail hard.
func TestResolve_AutoChainMissingFileFallsThroughToEnv(t *testing.T) {
	// Not parallel — t.Setenv mutates process state.
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN_TEST", "from-env")

	missing := filepath.Join(t.TempDir(), "no-such-token-file")
	cfg := config.Token{
		Source:          config.TokenSourceAuto,
		File:            missing,
		EnvVar:          "OP_SERVICE_ACCOUNT_TOKEN_TEST",
		KeychainAccount: "unset-account",
	}
	got, src, err := token.Resolve(context.Background(), cfg, token.NewMemoryStore())
	if err != nil {
		t.Fatalf("auto mode with a missing file should fall through, got error: %v", err)
	}
	if got != "from-env" || src != "env" {
		t.Fatalf("token/source = %q/%q, want %q/%q", got, src, "from-env", "env")
	}
}

func TestResolve_AutoChainAllEmptyReturnsError(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore()
	cfg := config.Token{
		Source:          config.TokenSourceAuto,
		EnvVar:          "OP_SERVICE_ACCOUNT_TOKEN_UNSET_FOR_TEST",
		KeychainAccount: "unknown-account",
	}
	_, _, err := token.Resolve(context.Background(), cfg, store)
	if err == nil {
		t.Fatalf("Resolve with no sources populated: want error, got nil")
	}
}

func TestResolve_ExplicitSourceUsesOnlyThatSource(t *testing.T) {
	// Not parallel — t.Setenv.
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN_TEST", "from-env")

	store := token.NewMemoryStore()
	_ = store.Set(context.Background(), "default", "from-keychain")
	filePath := writeTokenFile(t, "from-file")

	cases := []struct {
		name       string
		source     config.TokenSource
		wantToken  string
		wantSource string
	}{
		{"file source", config.TokenSourceFile, "from-file", "file"},
		{"env source", config.TokenSourceEnv, "from-env", "env"},
		{"keychain source", config.TokenSourceKeychain, "from-keychain", "keychain"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Token{
				Source:          tc.source,
				File:            filePath,
				EnvVar:          "OP_SERVICE_ACCOUNT_TOKEN_TEST",
				KeychainAccount: "default",
			}
			got, src, err := token.Resolve(context.Background(), cfg, store)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tc.wantToken {
				t.Fatalf("token = %q, want %q", got, tc.wantToken)
			}
			if src != tc.wantSource {
				t.Fatalf("source = %q, want %q", src, tc.wantSource)
			}
		})
	}
}

func TestResolve_ExplicitSourceMissingReturnsError(t *testing.T) {
	t.Parallel()

	store := token.NewMemoryStore() // empty
	cfg := config.Token{
		Source:          config.TokenSourceKeychain,
		KeychainAccount: "absent",
	}
	_, _, err := token.Resolve(context.Background(), cfg, store)
	if err == nil {
		t.Fatalf("explicit keychain source with no entry: want error, got nil")
	}
}

// Trailing whitespace in a token file (the common case for `echo foo > file`)
// must be trimmed so the SDK doesn't reject the token.
func TestResolve_TrimsWhitespaceFromFileContents(t *testing.T) {
	t.Parallel()

	filePath := writeTokenFile(t, "  abc-123\r\n")
	cfg := config.Token{Source: config.TokenSourceFile, File: filePath}

	got, _, err := token.Resolve(context.Background(), cfg, token.NewMemoryStore())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "abc-123" {
		t.Fatalf("token = %q, want %q", got, "abc-123")
	}
}
