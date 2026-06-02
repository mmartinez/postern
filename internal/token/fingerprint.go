// Package token brokers the credential-vendor service-account token between
// the CLI and the OS keychain. It exposes a Store interface for backend-neutral
// access plus a Fingerprint helper that lets callers log a redacted reference
// to a token without leaking secret material. The concrete OS-keychain store
// is backed by 99designs/keyring.
package token

import "strings"

// fingerprintReveal is the number of characters shown at each end of a masked
// token. Anything shorter than (2 * fingerprintReveal + 1) characters is fully
// masked instead, so a short or oddly-shaped token cannot accidentally be
// reconstructed from its fingerprint.
const fingerprintReveal = 4

// Fingerprint returns a log-safe identifier for a token in the form
// "first4…last4". It is intentionally lossy: callers should use it whenever
// they want to refer to a token in audit output, telemetry, or error messages.
//
// Inputs shorter than 2*fingerprintReveal+1 characters are fully masked with
// '*' to prevent the endpoints from disclosing the whole secret. The empty
// string returns the literal "<empty>" so log lines remain unambiguous.
func Fingerprint(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) < 2*fingerprintReveal+1 {
		return strings.Repeat("*", len(s))
	}
	return s[:fingerprintReveal] + "…" + s[len(s)-fingerprintReveal:]
}
