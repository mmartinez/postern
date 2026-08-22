# Security model

Postern brokers credentials, so it is built to be paranoid about leakage. This
document describes what postern guarantees, what it logs, the threats it does
and does not defend against, and how it handles keys.

## Fail-closed

Once a request matches a rule, postern must never let it reach the upstream
without the injected credential. Any error in the resolve-or-inject path —
a missing token, a vendor outage, a malformed reference, or a panic anywhere in
the hook chain — results in a generic `502 Bad Gateway` to the agent, and the
upstream is **not contacted**. The error body returned to the client is one
generic constant ("postern: bad gateway") for every failure, so the agent
cannot tell a missing token from a network blip from a misconfigured rule.
Connection-level
failures — a tunnel that cannot dial, or a mid-tunnel copy error — return the
same generic `502` body rather than the underlying error text, so a hostile
agent cannot use postern's errors to probe internal network topology.

This is an enforced invariant, not a convention: integration tests assert that
on a resolver error the upstream-side request counter stays at zero.

## Credential caching and revocation window

Resolved credentials are cached in memory and refreshed in the background so the
request path does not call the vault on every request (see
[configuration.md](configuration.md#proxycache)). This has a security
consequence worth stating explicitly: **serve-stale extends how long a revoked
credential can keep being injected.** If a credential is revoked or rotated at
the vault while the vault is simultaneously unreachable for refreshes
(rate-limit, outage), postern keeps serving the last-known-good value for up to
`proxy.cache.max_stale` (default 24h) before it fails closed. A credential that
was **never** successfully resolved is never served — only a previously-good
value is served stale.

The trade-off is deliberate: it is what keeps a transient vault hiccup from
turning into a 502 storm. `max_stale` is the knob that bounds the exposure
window. Revocation-sensitive deployments should lower it; setting
`max_stale == ttl` disables stale-serving entirely (the cache then fails closed
as soon as a value is past `ttl` and a refresh has failed). One-time-password
references are never cached, regardless of these settings.

## What is logged, and what is never logged

Logging is structured (`log/slog`, text or JSON). Postern emits a per-request
summary (method, host, status) plus, at higher verbosity, the per-stage
`proxy request` / `broker injected` / `proxy response` lines.

Never written to any log, stdout, stderr, file, or test fixture:

- A resolved credential value.
- A fingerprint or hash of a credential value.
- The contents of credential-bearing request headers. `Authorization`,
  `Cookie`, `Set-Cookie`, and token-bearing vendor headers (`x-api-key`,
  `x-amz-security-token`, and the `*-key` / `*-token` / `*-secret` families) are
  redacted from request logging.

When a token must be referenced in human-facing output, it is masked to a
`first4…last4` form via a dedicated helper, never shown in full.

## Threat model

**Defended:**

- *Credential theft from the agent.* The agent never holds the real secret, so
  prompt injection or a compromised dependency in the agent has nothing to
  exfiltrate beyond placeholders. This holds only for **correctly-scoped
  rules** and a **process/uid boundary** between the agent and postern — see
  the two caveats below.
- *Accidental credential logging.* Redaction and the no-secret-in-logs rule
  reduce the chance a credential lands in a log aggregator.
- *Silent auth bypass.* Fail-closed means a broker failure cannot degrade into
  an unauthenticated upstream call.

**Not defended (out of scope):**

- *A compromised postern process.* Postern holds live credentials in memory by
  design; an attacker with code execution in the postern process, or who can
  read its memory, can obtain them. Run it as the same trust principal as the
  credentials it brokers.
- *A stolen CA private key.* Anyone who can read `~/.postern/ca.key` can mint
  certificates the agent will trust. Protect it like any private key.
- *A malicious upstream or DNS hijack.* Postern validates upstream TLS, but it
  does not pin upstream certificates.
- *Credential delivery under an over-broad wildcard rule.* A `*.` rule injects
  the credential into **every** matching host, including ones the agent or an
  attacker can stand up. On a multi-tenant or shared-suffix domain
  (`*.s3.amazonaws.com`, `*.blob.core.windows.net`, …) a prompt-injected agent
  can request its own tenant under that suffix and have the credential
  delivered there over verified TLS — the provider's own wildcard certificate
  makes the handshake succeed. Use literal hosts; reserve wildcards for
  single-tenant domains you control. Postern cannot tell a single-tenant
  wildcard from a multi-tenant one, so this is the operator's responsibility.
- *Egress control.* Postern is a credential broker, not a firewall. Its
  `on_no_match: block` policy denies proxied requests that match no rule, but it
  governs only traffic routed through the proxy. See the note on `on_no_match`
  below.

## Key and token handling

**Local CA.** `postern ca install` generates a CA at `~/.postern/ca.{pem,key}`
(`0600` files under a `0700` directory) and adds the certificate to the system
trust store. On macOS it instead anchors the certificate at
`~/.postern/trust/ca.pem` and records a **user-domain** trust setting in your
login keychain via `/usr/bin/security add-trusted-cert`: per-user, not
system-wide, which is why no `sudo` is required (the authorization prompt the
command triggers is expected). System-wide (admin-domain) trust is a deliberate
follow-up, not current behavior. `postern ca uninstall [--purge]` reverses it:
on macOS that revokes the user-domain trust settings of every Postern CA
certificate the login keychain reports (`security remove-trusted-cert`) and
removes the anchor PEM; the keychain entries themselves deliberately stay,
since a self-signed root without explicit trust settings is untrusted by
macOS anyway.
The CA private key never leaves the machine and is used only to mint
short-lived per-host leaf certificates at request time.

**`SSL_CERT_FILE` and GUI clients.** `postern bootstrap` prints an
`SSL_CERT_FILE` export unconditionally. On macOS that variable is honored by Go
programs and OpenSSL-linked CLIs (such as `curl`), but GUI apps and browsers
ignore it: an agent that is a browser or other GUI client needs the keychain
trust installed by `postern ca install` instead.

**Service-account token.** Postern obtains the credential vendor's
service-account token through a resolution chain. With `source: auto` it tries,
in order: a token file, an environment variable, then the OS keychain. The
keychain-backed store uses the platform secret service; for headless or
container deployments, prefer a `0600` token file (e.g. mounted at
`/run/secrets/...`) or an environment variable.

Never pass a service-account token on a command line — it would be visible in
the process table. Use a file or environment variable.

An environment-variable token lives in postern's process environment for the
process lifetime and is readable via `/proc/<pid>/environ` by anything running
as the **same uid**. That is the "read its memory" threat above, but a `0600`
token file shrinks the exposure (the value is not in the env block). For any
deployment where the agent and postern might share a uid — including the
local-dev quick start — prefer `source: file`, and run postern as a separate
principal from the agent when you can.

**Validation at boot.** Each configured credstore validates its token with a
cheap read-only ping before the proxy binds its listener. A bad token fails the
process at startup rather than surfacing as a `502` on the first brokered
request.

## Egress containment with `on_no_match`

`proxy.on_no_match` controls what happens to a `CONNECT` whose host matches no
broker rule:

- `passthrough` (the default) tunnels the connection untouched — postern does
  not terminate TLS for it. The agent reaches the real upstream with the real
  certificate, and clients only need to trust the postern CA for hosts that are
  actually brokered.
- `block` rejects the `CONNECT` with a `502` and never contacts the upstream —
  an allowlist-only egress policy for traffic flowing through the proxy.

`block` governs only requests that reach the proxy. It is not a substitute for a
network-level egress policy: anything that bypasses the proxy (raw sockets,
misconfigured `HTTPS_PROXY`, non-HTTP protocols) is unaffected. Use a firewall
when you need to contain egress the process cannot route around.

## Selective interception

Postern terminates TLS only for hosts that match a broker rule; everything else
is tunneled byte-for-byte (or rejected under `block`). This shrinks the blast
radius — postern decrypts only what it brokers — and lets protocol upgrades
(e.g. WebSockets) and TLS-fingerprinting upstreams work end to end for
non-brokered hosts, since those connections carry the agent's own handshake to
the real server. Two boundaries follow from this:

- **The interception decision uses the outer `CONNECT` host (the SNI/authority
  the agent dials), not an inner request header.** A request that reaches a
  brokered host by fronting it behind a different, non-brokered `CONNECT` host
  would be tunneled, not brokered. This matters only under deliberate
  domain-fronting; for the intended use (an agent dialing an API directly) the
  `CONNECT` host and the request host are the same.
- **Brokered hosts that also need a WebSocket upgrade are still MITM'd**, and
  that upgrade path is not yet handled. Selective interception fixes upgrades
  for non-brokered hosts only.
