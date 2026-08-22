# Feature proposals

Top 3 gaps from a codebase survey of the working tree at `6b88df8` (2026-08-22).
Line references point at this tree.
Alternatives considered and skipped: Windows support (explicitly deferred pending demand, README.md:57), per-rule cache TTL overrides (niche; proxy-wide cache with max_stale already covers vault outages), SOCKS5 ingress (no agent ecosystem pressure; HTTPS_PROXY is the universal agent knob).

## Proposal 1: Per-rule request scoping (`paths:` / `methods:`)

> **Status: shipped.** Implemented as the `paths` / `methods` rule fields.
> The text below is kept as written at `6b88df8`, so problem and evidence
> sections describe the pre-implementation tree. Authoritative reference:
> [configuration.md → Request scoping](configuration.md#request-scoping-paths--methods).

### Problem
A rule brokers every request to its host.
An agent permitted to call `api.anthropic.com` can send any method to any path on that host, and postern attaches the real credential to all of it.
The stated threat model is a prompt-injected or compromised agent (README.md:20-23), and "any endpoint on the brokered host, with the key" is precisely the surface such an agent exploits.
Scoping injection to declared path prefixes and methods shrinks the blast radius from "whole host" to "the endpoints the rule exists for", which is the product's own thesis applied one level deeper.

### Evidence
- internal/config/schema.go:258-278: `Rule` fields are `template`, `host`, `secret_ref`, `inject`/`injects`, `routes` only; there is no path or method field.
- internal/broker/rule.go:165-190: `Match` is hostname-only (literal or single-label TLS-wildcard glob).
- internal/broker/hook.go:29-48: the hook brokers every request whose host matched; no path/method stage exists between match and inject.
- `grep -i 'paths|methods|PathPrefix'` over internal/config and internal/broker returns no matches.
- Per-rule knob precedent already exists: `Inject.MaxBodyBytes` (internal/config/schema.go:302-305) and the hook honors it (internal/broker/hook.go:55-57), so schema, validator, and hook extension points are established.
- Fail-closed behavior for scoped-out requests has an in-repo model: unknown/ambiguous route tokens 502 without calling the resolver (docs/ideas/placeholder-token-routing.md:58-59, implemented in `SelectRoute`, internal/broker/rule.go:53-89).

### Acceptance criteria
- [x] A rule declaring `paths: ["/v1/messages"]` injects for requests under that prefix and returns the uniform fail-closed 502 (`failClosedBody`, internal/broker/hook.go:246) for every other path, with the resolver provably never called (test asserts resolver call count is 0 on the 502 path).
- [x] A rule declaring `methods: [POST]` injects for POST and 502s GET with the resolver never called.
- [x] A rule with no `paths`/`methods` behaves exactly as today: the full existing broker and config test suites pass without modification.
- [x] `postern config validate` emits line-numbered lint errors for an empty `paths` or `methods` list and for a `paths` entry not starting with `/`.
- [x] Scoped-out 502s are indistinguishable from other broker 502s on the wire (same `failClosedBody`, no stage-revealing headers), per the oracle-avoidance rule at internal/broker/hook.go:240-245.

## Proposal 2: Credstore-qualified secret refs (two accounts of one vendor)

> **Status: shipped.** Implemented as the `<scheme>+<name>://` secret-ref
> grammar with name-keyed routing and ambiguity validation. Authoritative
> references: [configuration.md → `credstores`](configuration.md#credstores)
> and [providers.md](providers.md).

### Problem
Two credstores of the same vendor are rejected at boot, so one postern instance cannot serve two 1Password service accounts (personal vs team) or two Bitwarden organizations (prod vs staging).
Operators needing both today must run two postern processes with two configs, two CAs, and two proxy ports.
The schema and the broker both reserve the extension point; only the routing half was never built.

### Evidence
- internal/cli/server.go:310-311: boot fails with `credstores %q and %q both resolve to scheme %q (multiple credstores per provider not yet supported)`.
- internal/cli/server.go:297-299: author-flagged as "not yet implemented".
- internal/config/schema.go:88-96: `Name` is display-only today; the documented future shape is "routing key on Name and extend the secret_ref grammar to name its credstore", and `Name` was kept in the grammar so this change need not break config files.
- internal/broker/hook.go:23-27 and internal/broker/hook.go:42-43: `Resolver.Resolve(ctx, vaultID, secretRef)` carries a `vaultID` parameter "reserved for future multi-vault routing" that every provider forces to the empty string today.
- internal/config/validator.go:195-196: duplicate credstore names are already a lint error, so the name key needed for routing is validated but unused.

### Acceptance criteria
- [x] A config declaring two `op` credstores with distinct names boots, and a rule using a credstore-qualified ref (proposed grammar: `op+<name>://Vault/Item/field`, e.g. `op+team://Agents/Anthropic/api_key`) resolves from the named credstore; a test asserts the two same-scheme credstores hit different resolvers.
- [x] An unqualified `op://` ref while two `op` credstores are declared fails `postern config validate` with a line-numbered error naming the ambiguous scheme and the two credstore names.
- [x] Single-credstore configs, including the legacy top-level `token:` form (internal/config/schema.go:66-81), load and validate with no changes to existing tests.
- [x] Hot reload swaps a multi-credstore ruleset atomically with in-flight requests unaffected, extending the existing reloader test pattern (internal/broker/reloader_test.go).
- [x] `postern rules list` shows the credstore name each rule's ref resolves against, and never a resolved credential value.

## Proposal 3: Admin health endpoint for daemon deployments

> **Status: shipped.** Implemented as `proxy.admin_listen` with `GET
> /healthz`, the `postern server healthcheck` subcommand, and a compose
> `healthcheck`. Authoritative reference:
> [configuration.md → `proxy.admin_listen`](configuration.md#proxyadmin_listen).

### Problem
A running postern exposes no machine-checkable health surface.
Operators cannot distinguish "listening" from "serving with a validated credstore and a loaded ruleset", container orchestrators cannot healthcheck the service, and the only post-boot signals are log lines.
The boot-time credstore ping proves validity once (internal/cli/server.go:334-343); nothing re-exposes state after boot.

### Evidence
- internal/runtime/runtime.go:35-83: `Options` carries no admin/status surface; the `Runtime` binds exactly one listener, the proxy (internal/runtime/runtime.go:87-101, 179-220).
- docker-compose.yml:31-44: the example deployment has no `healthcheck` and no endpoint one could point one at; `restart: unless-stopped` is the only recovery mechanism.
- The CLI surface is `ca`, `config`, `token`, `rules`, `server`, `bootstrap` only (docs/architecture.md:108); there is no `status` command and the proxy port answers proxied traffic, not probes.
- Per-request summary logging exists (internal/logging/summary.go:20-34) but requires log scraping rather than a probe.

### Acceptance criteria
- [x] A new optional `proxy.admin_listen` field (schema + validator + line-numbered lint) starts a second HTTP listener; unset keeps behavior identical and all existing tests pass unchanged.
- [x] `GET /healthz` on the admin listener returns `200` with JSON containing `status`, the loaded ruleset version (incremented per hot reload), and credstore names with their last validation result; it returns `503` when no ruleset is loaded (brokerless passthrough mode).
- [x] The admin listener refuses to bind a non-loopback address: config validation errors with a line number before the server starts.
- [x] The admin endpoint never returns or logs credential material, secret refs beyond the rule count, or resolved values (test asserts response bodies against a credential-bearing fixture).
- [x] docker-compose.yml gains a `healthcheck` targeting `/healthz` on the admin port, and the response to a killed credstore token (validation failing) is observable in `/healthz` output.
