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
agent                     postern (127.0.0.1:14321)                 upstream
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

1. **CONNECT + MITM.** The agent points `HTTPS_PROXY` at postern. For each
   `CONNECT`, postern mints a short-lived leaf certificate for the target host,
   signed by a CA it generated locally and that the agent's trust store has been
   told to trust (`postern ca install`). The agent completes a normal TLS
   handshake; postern is the other end.

2. **Match.** The decrypted request's host (with any `:port` stripped) is
   matched against the YAML-declared rules — first match wins. Host patterns are
   either a literal hostname or a single-`*` glob (`*.example.com`, matching one
   label like a TLS wildcard). No match means the request is forwarded unchanged
   (the default `passthrough` behavior).

3. **Resolve.** The matched rule's `secret_ref` (e.g. `op://Vault/Item/field`)
   is handed to the credstore provider registered for that URI scheme. Resolved
   values are cached with a TTL and an LRU bound; one-time-password references
   bypass the cache. Resolver errors are never cached.

4. **Inject.** The resolved credential is rendered through the rule's template
   (`Bearer {{ CREDENTIAL }}`) and either set as a named header or substituted
   for a placeholder token already present in the request.

5. **Forward.** Postern forwards the now-authenticated request and streams the
   response back to the agent without buffering, so server-sent events and other
   incremental responses arrive as they are produced.

If resolution or injection fails at step 3 or 4, postern **fails closed**: it
returns a generic `502` to the agent and never contacts the upstream. See
[security.md](security.md).

## Trust boundary

The real credential exists only inside the postern process and on the wire
between postern and the upstream. It crosses to the agent's side **never**:

- The agent holds no credential — only the placeholder it sent (if any).
- `postern rules list` shows the `secret_ref`, never a resolved value.
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
| `internal/broker` | Host matching (`Engine`), credential injection (`Inject`), and the proxy hook that wires match → resolve → inject. |
| `internal/credstore` | Provider registry keyed by URI scheme, plus the `SchemeRouter` that dispatches a `secret_ref` to the right provider. |
| `internal/credstore/onepassword` | The production provider, backed by the 1Password Go SDK, plus the shared TTL/LRU resolver cache. |
| `internal/config` | YAML schema, strict-mode loader, line-numbered validator, and the fsnotify-backed hot-reload watcher. |
| `internal/token` | Service-account token resolution chain (file → env → keychain) and the OS-keychain-backed store. |
| `internal/runtime` | Assembles the proxy listener, wires the broker hook, and owns graceful shutdown. |
| `internal/cli` | Cobra commands: `config`, `token`, `ca`, `server`, `rules`, `bootstrap`. |
| `internal/logging` | slog factory (text/JSON, level, color) and the per-request summary handler. |

## Hot reload

`postern server` watches the config file. On save it re-parses and re-validates;
a clean parse atomically swaps the broker's ruleset so in-flight requests are
unaffected. A config with a fatal lint is rejected and the previous ruleset
keeps serving — the proxy never drops to an empty ruleset on a typo. Listener,
cache, and token settings are bound at startup; changing them requires a
restart, and postern logs a warning when a reload diverges on one of them.

## Pluggable credential vendors

The broker depends only on a one-method `Resolver` interface, so it has no
compile-time coupling to any vendor SDK. A credstore provider claims a URI
scheme, validates its token at boot, and constructs a resolver. Adding a vendor
is a single new sub-package plus a side-effect import in `main`; the broker,
proxy, and CLI are untouched. The contract is in [providers.md](providers.md).
