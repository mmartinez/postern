package bitwarden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// secretRefScheme is the bw:// URI prefix every bitwarden secret reference
// carries; Resolve strips it to recover the bws secret id.
const secretRefScheme = "bw://"

// ErrMalformedRef is returned when a bw:// reference does not carry a
// UUID-shaped secret id, so a typo fails closed before any subprocess fork.
var ErrMalformedRef = errors.New("malformed bw:// secret reference")

// secretJSON is the subset of `bws secret get --output json` postern reads.
// The secret's value is the credential; key/note are not brokered.
type secretJSON struct {
	Value string `json:"value"`
}

// bwsResolver resolves bw://<uuid> references by shelling out to bws. It is
// constructed per credstore by Provider.NewResolver and holds the parsed
// settings plus the access token, so the Provider singleton stays stateless.
type bwsResolver struct {
	runner    runner
	token     string
	serverURL string
}

// Resolve runs `bws secret get <uuid> --output json` and returns the secret's
// value. vaultID is reserved for future multi-vault routing and must be empty.
// A malformed reference or any bws failure fails closed without surfacing a
// partial value, so the broker returns 502 and never contacts the upstream.
func (r *bwsResolver) Resolve(ctx context.Context, vaultID, secretRef string) (string, error) {
	if vaultID != "" {
		return "", fmt.Errorf("vaultID-scoped resolution is not implemented (vaultID=%q)", vaultID)
	}
	id, ok := strings.CutPrefix(secretRef, secretRefScheme)
	if !ok || !looksLikeUUID(id) {
		return "", fmt.Errorf("%w: %q", ErrMalformedRef, secretRef)
	}

	args := []string{"secret", "get", id, "--output", "json"}
	if r.serverURL != "" {
		args = append(args, "--server-url", r.serverURL)
	}
	out, err := r.runner.run(ctx, args, bwsEnv(r.token))
	if err != nil {
		return "", fmt.Errorf("bws secret get: %w", err)
	}

	var parsed secretJSON
	if err := json.Unmarshal(out, &parsed); err != nil {
		// Do NOT wrap the json error: encoding/json echoes the first offending
		// input byte ("invalid character 's' ...") into its message, which for
		// non-JSON stdout would be a byte of the secret. Return a fixed message
		// so no fragment of the credential can reach a log.
		return "", errors.New("bws output was not valid json")
	}
	if parsed.Value == "" {
		return "", errors.New("bws returned an empty secret value")
	}
	return parsed.Value, nil
}

// bwsEnv is the minimal, non-inherited environment for a bws invocation: the
// access token (via env, never argv, so it cannot leak through ps/proc) plus
// PATH. Nothing else from os.Environ is forwarded.
func bwsEnv(token string) []string {
	env := []string{"BWS_ACCESS_TOKEN=" + token}
	if p := os.Getenv("PATH"); p != "" {
		env = append(env, "PATH="+p)
	}
	return env
}

// looksLikeUUID reports whether s has canonical 8-4-4-4-12 hex UUID shape. It
// is a cheap pre-fork guard, deliberately format- (not version-) strict, so an
// obviously malformed id fails closed without a network round-trip.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(c) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
