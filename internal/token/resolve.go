package token

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mmartinez/postern/internal/config"
)

// Resolve walks the token-resolution chain and returns the first
// non-empty token along with a short label identifying which source
// provided it ("file", "env", or "keychain"). Source-specific labels
// surface in `postern token status` and audit logs.
//
// cfg.Source = "auto" walks file → env → keychain. Any other source pins
// resolution to that step. Every source that yields no token is treated
// as "not present" (not as an error) so the chain can continue, but a
// pinned source that yields nothing returns an error so a misconfigured
// pin fails closed instead of silently degrading.
func Resolve(ctx context.Context, cfg config.Token, store Store) (tok, source string, err error) {
	switch cfg.Source {
	case config.TokenSourceFile:
		v, err := readFile(cfg.File)
		if err != nil {
			return "", "", err
		}
		if v == "" {
			return "", "", fmt.Errorf("token.source=file but %s is empty", cfg.File)
		}
		return v, "file", nil
	case config.TokenSourceEnv:
		v := os.Getenv(cfg.EnvVar)
		if v == "" {
			return "", "", fmt.Errorf("token.source=env but %s is unset or empty", cfg.EnvVar)
		}
		return v, "env", nil
	case config.TokenSourceKeychain:
		v, err := store.Get(ctx, cfg.KeychainAccount)
		if err != nil {
			return "", "", fmt.Errorf("token.source=keychain (account=%s): %w", cfg.KeychainAccount, err)
		}
		if v == "" {
			return "", "", fmt.Errorf("token.source=keychain (account=%s) yielded empty value", cfg.KeychainAccount)
		}
		return v, "keychain", nil
	case config.TokenSourceAuto, "":
		// fall through to chain
	default:
		return "", "", fmt.Errorf("unknown token.source %q", cfg.Source)
	}

	if cfg.File != "" {
		v, err := readFile(cfg.File)
		// A missing file in auto mode is "not present", not a failure: the
		// file is one option among several, so fall through to env/keychain
		// (mirroring the keychain branch's ErrNotFound handling below). A
		// non-NotExist read error (e.g. permission denied) is a real backend
		// failure and still aborts.
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return "", "", err
		case v != "":
			return v, "file", nil
		}
	}

	if cfg.EnvVar != "" {
		if v := os.Getenv(cfg.EnvVar); v != "" {
			return v, "env", nil
		}
	}

	if cfg.KeychainAccount != "" {
		v, err := store.Get(ctx, cfg.KeychainAccount)
		if err == nil && v != "" {
			return v, "keychain", nil
		}
		// ErrNotFound is the normal "no entry" signal; anything else is a
		// real backend failure that the operator should hear about. The
		// chain falls through on either so a missing keychain doesn't
		// shadow a working env var on a subsequent run, but the error is
		// included in the final summary below.
		if err != nil && !errors.Is(err, ErrNotFound) {
			return "", "", fmt.Errorf("token chain: keychain lookup for %s failed: %w", cfg.KeychainAccount, err)
		}
	}

	return "", "", errors.New("no service-account token found; run `postern token set` or set " +
		cfg.EnvVar + " or populate " + cfg.File)
}

// readFile returns the token contents of path with leading/trailing
// whitespace trimmed. A missing file is an error; an empty file is
// signalled by an empty return value rather than an error so the chain
// can fall through.
func readFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // user-supplied token-file path is intentional
	if err != nil {
		return "", fmt.Errorf("read token file %s: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}
