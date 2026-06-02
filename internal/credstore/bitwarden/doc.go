// Package bitwarden implements a credstore.Provider backed by the Bitwarden
// Secrets Manager CLI (bws). Postern shells out to the bws binary rather than
// linking the GPL-3.0 Go SDK, which keeps this provider pure Go and every
// published postern artifact license-clean.
//
// A bw://<secret-uuid> reference resolves to the secret's value via
// `bws secret get`; the machine-account access token is supplied per credstore
// and passed to bws through a minimal, non-inherited environment so it never
// reaches argv. A self-hosted deployment sets settings.server_url, forwarded as
// the per-invocation --server-url flag.
package bitwarden
