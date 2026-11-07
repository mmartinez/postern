# Postern troubleshooting

Start with the server log at `--log-level info` (the default) or `debug`.
A brokered request logs `broker injected host=<host>`; `quiet` hides that line, and a daemonized process discards its output entirely.

| Symptom | Diagnosis |
|---|---|
| `502` with body `postern: bad gateway` on a matched request | Uniform fail-closed result. Sources: missing or invalid token, unresolvable secret ref, vault outage, sentinel absent, no matching route token, request outside `paths`/`methods`, no live approval grant. A resolver, scope, or approval refusal never contacts the upstream; a response-scrub refusal happens after the upstream responds (see below). |
| Upstream returns 401/403 but postern is configured | Possible causes: the request bypassed the proxy, it matched no rule, or the injected credential is revoked or lacks permission. A `broker injected` line for that request means the credential reached the upstream, so question the credential rather than the wiring. |
| Upstream returns 401/403 and no `broker injected` line | The client bypassed the proxy. Node needs `NODE_USE_ENV_PROXY=1`; clients with their own proxy agent or `ca` option ignore the environment. |
| `x509: certificate signed by unknown authority` | That client does not trust the CA. Use `postern bootstrap`, `NODE_EXTRA_CA_CERTS`, keychain trust on macOS, or the system store on Linux. If the CA was regenerated, reinstall and re-export. |
| `502` for a host with no rule | Under `on_no_match: block` this is the intended allowlist behavior. Check the setting before changing anything. |
| `413 Request Entity Too Large` | The body exceeds `proxy.max_body_bytes` (default 1 MiB) on a rule that rewrites the body. |
| `502` on responses from a brokered host | Response scrubbing could not inspect a compressed response and failed closed. |
| Config edit has no effect | Listener, cache, `admin_listen`, token, `on_no_match`, `scrub_responses`, and `max_body_bytes` are bound at startup. Restart. A server started with zero rules does not watch the file. |
| `postern server` exits immediately | Missing CA (`postern ca install`), invalid config (validate it), a token that failed the boot-time vendor check, or a listener port already in use. |
| Approval dialog never appears | The polkit action is not installed, no polkit authentication agent runs in the desktop session, or the build has no backend (non-cgo macOS). A live grant, the 30s cooldown after a denial, or the refusal budget also suppress prompts. |
| A daemonized server logs nothing | `postern server --daemon` detaches and discards stdout and stderr. Run in the foreground or under a service manager that captures logs. |
| `fopen ... permission denied` on the config or CA | The agent runs as a different uid than the one that owns `~/.postern`. Have the user make the edit, or read a certificate-only copy at a 0644 path. |
| `bws: executable file not found` | The Bitwarden provider shells out to `bws`; install it from Bitwarden and put it on postern's `PATH`, or set `settings.bws_path`. |
| `postern token status` reports no token, or `token test` fails | No token is stored for that account, or the vendor rejects it. The user must supply a valid token; do not guess or reuse another. |
| Placeholder request fails with 502 | The client did not send the configured sentinel, or sent it on a surface the rule does not scan (`inject.in`). |

A cached credential keeps serving for up to `proxy.cache.max_stale` (default 24h) while refreshes fail, so a revoked secret can stay injectable for that window.
Lower `max_stale`, or set it equal to `ttl`, for revocation-sensitive secrets.

With `proxy.admin_listen` set, `postern server healthcheck --addr <addr>` exits 0 only on a healthy `200`.
`GET /healthz` reports status, `ruleset_version`, and per-credstore validity, never credentials or references.

Full reference lives in the postern source tree: `docs/configuration.md`, `docs/security.md`, `docs/providers.md`, also published at https://github.com/mmartinez/postern/tree/main/docs.
Every command has `postern <command> --help`.
