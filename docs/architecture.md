# Architecture

Postern is a TLS-intercepting forward HTTP proxy that injects credentials into
outbound requests on behalf of an agent, so the agent never holds the real
secret. This document traces a request through the system and describes the
trust boundary and the component layout.

## The problem it solves

An AI agent that calls authenticated APIs needs credentials. If those
credentials live in the agent's environment, prompt injection or a compromised
dependency can read and exfiltrate them. Postern moves the secret out of the
agent's reach: the agent makes the call with no `Authorization` header (or a
placeholder), and postern attaches the real credential on the way out.

## Request lifecycle

```
agent                     postern (127.0.0.1:1701)                 upstream
  │                              │                                     │
  │  CONNECT api.example.com:443 │                                     │
  ├─────────────────────────────▶                                     │
  │                              │  mint per-host leaf cert from       │
  │                              │  the local CA, complete TLS         │
  │  ◀───── TLS (postern cert) ──┤                                     │
  │                              │                                     │
  │  GET /v1/things  (no auth)   │                                     │
  ├─────────────────────────────▶  1. match host against rules        │
  │                              │  2. resolve rule's secret_ref       │
  │                              │     from the credential vendor      │
  │                              │  3. inject credential into request  │
  │                              │                  4. forward ────────▶
  │                              │                                     │
  │                              │  ◀──────────────── response ────────┤
  │  ◀──── response (streamed) ──┤                                     │
```

1. **CONNECT + selective MITM.** The agent points `HTTPS_PROXY` at postern. For
   each `CONNECT`, postern matches the target host against the rules and
   intercepts only brokered hosts: it mints a short-lived leaf certificate for
   the host, signed by a CA it generated locally and that the agent's trust
   store has been told to trust (`postern ca install`), and completes the TLS
   handshake as the other end. A host that matches no rule is tunneled untouched
   — postern relays the encrypted bytes without terminating TLS, so the agent
   reaches the real upstream with the real certificate and only needs to trust
   the postern CA for hosts it actually brokers. (When no broker is configured
   at all, postern falls back to intercepting every host.)
   Inner requests on an intercepted tunnel are bound to the CONNECT
   authority; a decrypted request naming any other authority (host and port)
   fails closed with a 502.

2. **Match.** For an intercepted host the decrypted request's host (with any
   `:port` stripped) is matched against the YAML-declared rules — first match
   wins. Host patterns are either a literal hostname or a single-`*` glob
   (`*.example.com`, matching one label like a TLS wildcard). A single
   trailing dot is stripped from the wire host and from the rule pattern
   alike, exactly once, so a dotted FQDN decides identically to its bare
   form; a malformed multi-dot authority matches nothing and falls through
   to the configured `passthrough`/`block` policy. A rule may further scope
   itself with `paths` / `methods`: a matched request outside that scope
   fails closed exactly like any other broker refusal (the same generic
   `502`, resolver never called), revealing no stage information. A host
   that matches no rule is tunneled at `CONNECT` without decryption (the
   default `passthrough` behavior); `block` rejects the `CONNECT` instead.

3. **Resolve.** The matched rule's `secret_ref` is dispatched by its URI
   scheme — plus its optional `<scheme>+<name>://` qualifier when several
   credstores of one vendor are configured — to the provider registered for
   that scheme. Resolved values are cached with a TTL; entries are keyed by
   secret reference, never evicted, and survive hot reloads — the cache
   footprint is bounded by the set of references seen over the process
   lifetime. One-time-password references bypass the cache. Failed
   resolutions are retried after a backoff window and are never served as
   values.

4. **Inject.** The resolved credential is rendered through the rule's template
   (`Bearer {{ CREDENTIAL }}`) and either set as a named header or substituted
   for a placeholder token already present in the request.

5. **Forward.** Postern forwards the now-authenticated request and streams the
   response back to the agent without buffering, so server-sent events and other
   incremental responses arrive as they are produced.

Tunnel lifetime: hijacked tunnels are activity-tracked, not deadline-bound.
The reaper scans every 30s, so closure lands within the stated bound plus one scan.
A connection that has moved fewer than 128 bytes of total progress is closed roughly 30-60s after acceptance regardless of any intervening activity, while an established tunnel is closed after roughly 10m without two-way traffic (activity resets that longer timer, so live SSE streams are not cut).
Shutdown drains open tunnels within the remaining budget before force-closing whatever is still alive.

If resolution or injection fails at step 3 or 4, postern **fails closed**: it
returns a generic `502` to the agent and never contacts the upstream. See
[security.md](security.md).

## Trust boundary

The intended boundary: the real credential exists only inside the postern
process and on the wire between postern and the upstream.

- The agent holds no credential — only the placeholder it sent (if any).
  Postern does not scrub upstream responses: an upstream that reflects the
  injected credential back in its response can still expose it to the agent.
- `postern rules list` shows rule-level fields (host and `secret_ref`), never
  a resolved value.
- Logs redact credential-bearing headers and never print a resolved secret.

The local CA's private key is the other sensitive asset; it lives at
`~/.postern/ca.key` with `0600` permissions under a `0700` directory. Anyone who
can read it can mint trusted certificates for the user, so it is treated like
any other private key.

## Components

| Package | Responsibility |
|---|---|
| `internal/proxy` | goproxy front end: CONNECT handling, MITM, panic recovery, response streaming. |
| `internal/ca` | Local CA generation, per-host leaf minting, and system trust-store install. |
| `internal/broker` | Host matching (`Engine`), per-rule request scoping (`paths`/`methods`), credential injection (`Inject`), and the proxy hook that wires match → scope → resolve → inject. |
| `internal/credstore` | Provider registry keyed by URI scheme, the name-keyed `NameRouter` that dispatches a `secret_ref` (scheme plus optional `<scheme>+<name>://` qualifier) to one configured credstore instance, and the shared background-refreshing resolver cache (`cache.go`) every provider reuses. |
| `internal/credstore/onepassword` | Provider for 1Password Service Accounts (`op://`), backed by the 1Password Go SDK. Registered by default. |
| `internal/credstore/bitwarden` | Provider for Bitwarden Secrets Manager (`bw://`), shelling out to the `bws` CLI. Registered by default. |
| `internal/credstore/oauth2` | Provider that mints short-lived bearer tokens (`oauth2://`) via `golang.org/x/oauth2` (client-credentials / refresh-token grants). Registered by default. |
| `internal/config` | YAML schema, strict-mode loader, line-numbered validator, and the fsnotify-backed hot-reload watcher with a 5s stat-poll fallback that survives silent watch death (watcher errors are logged at Warn). |
| `internal/token` | Service-account token resolution chain (file → env → keychain) and the OS-keychain-backed store. |
| `internal/runtime` | Assembles the proxy listener plus the optional loopback-only admin listener (`GET /healthz`), wires the broker hook, and owns graceful shutdown, connection tracking, and tunnel reaping. |
| `internal/cli` | Cobra commands: `config`, `token`, `ca`, `server`, `rules`, `bootstrap`. |
| `internal/logging` | slog factory (text/JSON, level, color) and the per-request summary handler. |

## Hot reload

A started server with zero rules runs brokerless and does not watch the
config file: adding the first rule requires a restart. Otherwise `postern
server` watches the config file. On save it re-parses and re-validates;
a clean parse atomically swaps the broker's ruleset so in-flight requests are
unaffected. Each applied swap increments the ruleset version by exactly one;
the admin health endpoint (`GET /healthz` on `proxy.admin_listen`) surfaces
that version so orchestrators can observe that a config change landed. A
config with a fatal lint is rejected and the previous ruleset keeps serving,
so the proxy never drops to an empty ruleset on a typo. Listener, cache,
admin-listener, and token settings are bound at startup; changing them
requires a restart, and postern logs a warning when a reload diverges on one
of them (changes to a credstore's `refresh_token` block are not currently
detected).

## Pluggable credential vendors

The broker depends only on a one-method `Resolver` interface, so it has no
compile-time coupling to any vendor SDK. A credstore provider claims a URI
scheme, validates its token at boot, and constructs a resolver. One provider
(one claimed scheme) can back several configured credstore instances, selected
by the `<scheme>+<name>://` ref qualifier or resolved from an unambiguous
unqualified ref. Adding a vendor
is a single new sub-package plus one blank side-effect import in
`internal/cli/server.go` (the anchor block where all three shipped providers are
registered, so the `server` command's registry is populated); the broker and
proxy logic are untouched. The contract is in [providers.md](providers.md).
