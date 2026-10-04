# Feature proposals

Two codebase surveys live in this file, each written in the same
Problem / Evidence / Acceptance-criteria shape.

- **Survey 1 (2026-08-22, `6b88df8`)** — Proposals 1-3, below. All three shipped.
- **Survey 2 (2026-10-03, `ca04acb`, v0.9.1)** — Proposals 4-6, then a ranked
  backlog. Built from a six-slice subsystem graph (broker/proxy, config, credstore
  providers, ca/token, runtime/CLI, packaging/CI) cross-read against every doc
  claim. Two findings were reproduced at runtime inside the devcontainer and are
  marked **[reproduced]**; their throwaway repro tests were deleted after the
  run.

## Proposal 1: Per-rule request scoping (`paths:` / `methods:`)

> **Status: shipped.** Implemented as the `paths` / `methods` rule fields.
> The text below is kept as written at `6b88df8`, so problem and evidence
> sections describe the pre-implementation tree. Authoritative reference:
> [configuration.md → Request scoping](configuration.md#request-scoping-paths--methods).

### Problem
A rule brokers every request to its host.
An agent permitted to call `api.anthropic.com` can send any method to any path on that host, and postern attaches the real credential to all of it.
The stated threat model is a prompt-injected or compromised agent (README.md:29-30), and "any endpoint on the brokered host, with the key" is precisely the surface such an agent exploits.
Scoping injection to declared path prefixes and methods shrinks the blast radius from "whole host" to "the endpoints the rule exists for", which is the product's own thesis applied one level deeper.

### Evidence
> The evidence below is as-of the graph survey that produced this proposal, not
> a description of the tree today. Where the gap is closed, the line says so and
> cites where the fix landed — several of the original assertions are no longer
> true of the current code, and are marked rather than left to mislead.

- internal/config/schema.go:305-317: `Rule` now carries `Paths` and `Methods` alongside `template`, `host`, `secret_ref`, `inject`/`injects`, `routes`. At survey time those two fields did not exist — that absence is the gap this proposal closed.
- internal/broker/rule.go:165-190: `Match` is hostname-only (literal or single-label TLS-wildcard glob).
- internal/broker/hook.go:69: at survey time the hook brokered every request whose host matched, with no path/method stage between match and inject. Scoping is now step 2 of the hook (internal/broker/hook.go:38-42, enforced at `:93`) — see the acceptance criteria below.
- A `grep -i 'paths|methods|PathPrefix'` over internal/config and internal/broker returned no matches at survey time; it now matches `schema.go`, `rule.go`, and `validator_scoping.go`.
- Per-rule knob precedent already exists: `Inject.MaxBodyBytes` (internal/config/schema.go:342-345), and the hook lets the per-rule override win over the proxy-wide cap at internal/broker/hook.go:144 — so schema, validator, and hook extension points are established.
- Fail-closed behavior for scoped-out requests has an in-repo model: unknown/ambiguous route tokens 502 without calling the resolver (docs/ideas/placeholder-token-routing.md:58-59, implemented in `SelectRoute`, internal/broker/rule.go:53-89).

### Acceptance criteria
- [x] A rule declaring `paths: ["/v1/messages"]` injects for requests under that prefix and returns the uniform fail-closed 502 (`failClosedBody`, internal/broker/hook.go:291-297) for every other path, with the resolver provably never called (test asserts resolver call count is 0 on the 502 path).
- [x] A rule declaring `methods: [POST]` injects for POST and 502s GET with the resolver never called.
- [x] A rule with no `paths`/`methods` behaves exactly as today: the full existing broker and config test suites pass without modification.
- [x] `postern config validate` emits line-numbered lint errors for an empty `paths` or `methods` list and for a `paths` entry not starting with `/`.
- [x] Scoped-out 502s are indistinguishable from other broker 502s on the wire (same `failClosedBody`, no stage-revealing headers), per the oracle-avoidance rule at internal/broker/hook.go:291-297.

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
- internal/runtime/runtime.go:35-112: `Options` exposes no status endpoint on the proxy port. Its only listener field beyond `Addr` is `AdminListen` (`:105`), which starts a *second* loopback port for `GET /healthz` and defaults to empty. Nothing answers a probe on the proxy listener. `Runtime.Run` correspondingly binds the proxy listener at `:242` and the admin one only when configured (`:247-249`, conditional on `r.admin != nil`).
- docker-compose.yml:31-44: the example deployment has no `healthcheck` and no endpoint one could point one at; `restart: unless-stopped` is the only recovery mechanism.
- The CLI surface is `ca`, `config`, `token`, `rules`, `server`, `bootstrap` only (docs/architecture.md:128); there is no `status` command and the proxy port answers proxied traffic, not probes.
- Per-request summary logging exists (internal/logging/summary.go:20-34) but requires log scraping rather than a probe.

### Acceptance criteria
- [x] A new optional `proxy.admin_listen` field (schema + validator + line-numbered lint) starts a second HTTP listener; unset keeps behavior identical and all existing tests pass unchanged.
- [x] `GET /healthz` on the admin listener returns `200` with JSON containing `status`, the loaded ruleset version (incremented per hot reload), and credstore names with their last validation result; it returns `503` when no ruleset is loaded (brokerless passthrough mode).
- [x] The admin listener refuses to bind a non-loopback address: config validation errors with a line number before the server starts.
- [x] The admin endpoint never returns or logs credential material, secret refs beyond the rule count, or resolved values (test asserts response bodies against a credential-bearing fixture).
- [x] docker-compose.yml gains a `healthcheck` targeting `/healthz` on the admin port, and the response to a killed credstore token (validation failing) is observable in `/healthz` output.

---

# Survey 2 (2026-10-03, `ca04acb`)

## Market context (added after external research, 2026-10-03)

The graph survey below ranks by code-graph signal. External research says the
ranking is wrong in three places. This section records the market facts so the
backlog is read in the right order.

**Postern implements one delivery model, and it is worth naming precisely.** The
agent sends a request through postern; postern resolves the credential and
injects it; the agent never receives, sees, or holds the real value. That is
the whole of the security claim, and it holds on the response path too: the
credential injected on a request is stripped back out of the reply before the
agent sees it (`proxy.scrub_responses`, on by default; backlog #33, shipped).
The weaknesses of the model are the model's — two network hops, a single point
of failure, throughput — and postern emits no latency or throughput numbers at
all (backlog #1), so it cannot currently observe any of them.

> **Correction, 2026-10-03.** An earlier version of this section claimed
> *"postern already implements an industry-recommended primary model and does
> not say so."* **That was wrong, and the positioning built on it has been
> withdrawn.** A short-lived-token model exists in which the broker hands the
> token **to the agent** for a **direct** call to the target. Postern's `oauth2`
> provider mints a token and then **injects it into a request travelling
> through postern** like any other credential — every consumer of
> `broker.Resolver` is inside the MITM hook (`internal/broker/hook.go:185`,
> `:252`) and the only agent-facing surface is `GET /healthz`
> (`internal/runtime/admin.go:75-77`). It is the proxy-gateway model with a
> shorter-lived credential, not the hand-it-to-the-agent one. It is also not
> generic: `grant_type` accepts only `client_credentials` and `refresh_token`
> (`internal/credstore/oauth2/provider.go:212`), so RFC 8693 token exchange and
> RFC 7523 JWT-bearer assertion are both absent. The README, `providers.md`,
> `architecture.md`, and `security.md` have all been corrected; the honest line
> is **"one proxy, two credential sources: your vault, or your IdP"**, which
> needs no external draft at all.

**The threat model names postern's fail-open.** Injecting a credential is what
postern is for, and the pressure to *not* do it — under time, cost, or an
operator wanting traffic to flow — is the failure that matters most here.
Proposal 4 is exactly that failure, and the mitigation shape the expired draft
used is the shape Proposal 4 proposes: an explicit, named opt-out rather than a
silent downgrade. Multi-agent composition — correlating which agent made which
call — is mitigated by backlog #1 plus the `routes` per-agent attribution
postern already has.

**A direct competitor ships the same architecture.** HTTPS_PROXY, MITM,
placeholder substitution — with a commercial product layered behind it. Postern
will not out-distribute or out-UI anyone; it has to out-specify. Two claims this
document previously made about that competitor did not survive checking and are
withdrawn rather than restated: it does support OAuth credentials with automatic
proxy-side refresh and dynamic-secret leases, and it does have host path-scoped
matching. Neither was true of postern's own position either — this section had
been filing postern's gaps as differentiation in both directions, which is worth
owning.

**The differentiator that was missed, and it is the real one.** Serving a
last-known-good value after its source fails is a genuine risk: a revoked
credential keeps working for as long as the staleness window allows. Postern
bounds it. `proxy.cache.max_stale` is a deadline after which postern stops
serving and fails closed (`internal/credstore/cache.go:180`, default 24h), and it
is a knob an operator sets against their own revocation sensitivity. That turns
the deviation this document had been filing as a *liability* — serve-stale —
into a **differentiator**: the failure mode is bounded, visible and configurable
rather than unbounded and silent.

**On the demand driver, with the caveat.** The March 2026 TeamPCP compromise of
LiteLLM (~95M monthly PyPI downloads) is real and well corroborated. But the
mechanism was a malicious CI dependency on the *build host* shipping a credential
stealer — an argument for build and dependency integrity, not for a proxy. A
stealer with a shell on the host reads the same vendor token postern reads,
plus `~/.postern/ca.key`. Postern's own docs concede it: run postern as the same
trust principal as the credentials it brokers, or as a different one.

**Re-prioritisation.** Proposal 4 stays at the top — it is not merely a good
idea, it is the failure a security reviewer will find first. Proposal 5 is
unchanged: it is a correctness fix to validation coverage. Proposal 6
(`rules explain`) drops below time-to-first-brokered-request (#30 brew, #23
`ca export`, #27 Linux trust) — response scrubbing having since shipped (#33) —
because postern's binding constraint is not features, it is the install-and-
trust funnel. Backlog #29 (`bws` error message pointing at a nonexistent image)
also rises: a first-run dead end for anyone who picks the Bitwarden backend.

**What the re-prioritisation no longer claims.** The original framing here led
with a model taxonomy borrowed from a draft, as the differentiator. That was
withdrawn: postern implements one delivery model with two credential sources,
the vocabulary came from a draft that expired 2026-09-30, and the competitive
axis it was meant to win on is the one the competitor is ahead on. The
defensible differentiation is narrower and checkable — method-scoped rules the
competitor's matcher cannot express, first-class vault-provider support, and a
bounded fail-closed staleness deadline the competitor explicitly does not have.

## Proposal 4: Fail closed on a request postern cannot inject into

### Problem
The broker hook states its own invariant: "the proxy must never let an
unauthenticated request out to the upstream once it has matched a rule"
(internal/broker/hook.go:55-58). One path violates it.

When a placeholder rule declares `body` as its only surface and the request
carries a `Content-Encoding` other than `identity` (or a `multipart/*`
content type), postern resolves the real credential from the vault, injects
it nowhere, and forwards the request to the brokered upstream **unauthenticated**
— with the placeholder token still in the body. No 502 is returned, and the
request is logged at `info` as **`broker injected`**
(`internal/broker/hook.go:283`), because the hook reaches that line whenever
`Inject` returns nil. That log line is a false audit record: an operator
reading the trail sees a successful injection for a call that carried no
credential at all. It is the worst part of this failure, because it removes the
one signal an operator would otherwise have to notice it.

This is not an edge case the agent stumbles into. The agent chooses its own
request headers, and the threat model is precisely a prompt-injected or
compromised agent (README.md:29-30). Adding one request header converts every
credentialed call into an unauthenticated one, which is the exact blast radius
the product exists to close: the agent gets an authenticated *channel* to the
upstream without ever seeing the credential, and can drive the account to
exhaustion or abuse on the operator's dime.

The behaviour is deliberate and documented, which is what makes it worth a
proposal rather than a bug report — but the decision was made for the
injection layer in isolation and never reconciled with the module's invariant
or with what the sibling code path already does.

### Evidence
- internal/broker/hook.go:55-58 — the invariant, verbatim: "On any resolve or
  inject error the hook returns a synthesized 502 — fail closed: the proxy must
  never let an unauthenticated request out to the upstream once it has matched
  a rule."
- internal/broker/inject.go:219-220 — the documented exception, verbatim: "Zero
  eligible surfaces (e.g. a body-only rule on a compressed body) forwards the
  request untouched."
- internal/broker/inject.go:365-366 — `substituteBody` returns `skipped = true`
  for a compressed or multipart body, and inject.go:277-285 only increments
  `eligible` when `!skipped`. inject.go:291-294 then returns `nil` (success,
  forward) whenever `eligible == 0`, because the fail-closed `ErrNoPlaceholder`
  branch is guarded on `eligible > 0`.
- internal/broker/inject.go:348-353 — `bodySkippable` is the trigger: any
  `Content-Encoding` other than `identity`, or any `multipart/*` media type.
- internal/broker/hook.go:141 — buffering is skipped for the same requests, so
  the cap never applies; hook.go:287 returns `nil`, which goproxy treats as
  "forward it".
- internal/broker/routing_test.go:264-288 — **the sibling path already fails
  closed on the identical input.** `TestHook_RouteBodyCompressedFailsClosed`
  asserts a 502 *and* `resolver.calls == 0`. The asymmetry is not incidental.
- docs/configuration.md:296-298 and docs/configuration.md:392-394 — both
  halves of that asymmetry are written down, one after the other.
- **[reproduced]** A throwaway test against the current tree (since deleted)
  ran a body-only placeholder rule with `Content-Encoding: gzip` through
  `broker.Hook` and observed: `forward_to_upstream=true`, `resolver_calls=1`,
  body forwarded byte-for-byte as `{"api_key":"__tok__"}`, and the resolved
  value absent from the request entirely.

### Scope, and what an operator can do today

Two limits, so this proposal is not over-read:

- **Only body-only placeholder rules are affected.** A rule using the default
  header surface is not — `substituteHeaders` is unconditionally eligible, so
  `eligible > 0` and the `ErrNoPlaceholder` guard does its job. Operators on
  `type: header`, which is the common case, are not exposed.
- **Declaring a second injection surface closes the hole today.** Adding any
  other eligible surface to a body-only rule makes `eligible > 0`, which turns
  the zero-substitution case into a fail-closed `ErrNoPlaceholder` instead of a
  forward. That is a workaround, not a fix: it is undiscoverable, no doc says
  it, and it leaves the misleading log line in place. Treat a body-only
  placeholder rule as untrusted until this lands.

### Acceptance criteria
- [ ] The `broker injected` info record is emitted only when a substitution
  actually occurred. Today it fires whenever `Inject` returns nil, which on this
  path means nothing was injected — so the audit trail must not claim success
  for a request that went out unauthenticated. A regression test asserts the
  log line is absent on this path and present on a successful injection.
- [ ] A request whose rule matched but whose declared surfaces are all
  ineligible (body-only rule + compressed/multipart body) returns the uniform
  fail-closed `502` (`failClosedBody`, internal/broker/hook.go:306), and the
  resolver is provably never called — the check happens **before** resolve,
  matching the existing scope (hook.go:93) and https-only (hook.go:107) stages,
  which both fail closed without touching the vault.
- [ ] The eligibility check is a stage in the hook, not a late return from
  `substituteToken`, so the pointless vault round-trip is skipped too.
- [ ] An explicit per-rule opt-out restores the current forward-untouched
  behaviour for operators who depend on it (a body-scraping or file-upload
  rule, where there is no token to substitute at all). The opt-in must be
  visible in `docs/configuration.md` next to the surface table.
- [ ] Scoped-out 502s stay indistinguishable on the wire from every other
  broker 502 — same `failClosedBody`, no stage-revealing header — per the
  oracle-avoidance contract at internal/broker/hook.go:291-297.
- [ ] The `413` over-cap path (hook.go:320-339) is unchanged: an oversized body
  is still a client error, not a credential-handling failure.
- [ ] The four tests that pin today's behaviour
  (internal/broker/hook_surfaces_test.go:70-104,
  internal/broker/inject_surfaces_test.go:111-137,
  internal/broker/integration_surfaces_test.go:213-257) are either updated to
  the new default or kept as the opt-out case; none is deleted silently.
- [ ] A regression test asserts the upstream-side request counter stayed at
  zero on this path, matching the existing fail-closed tests.

### Alternatives considered
- **Transparently gunzip/gun-multipart and re-splice.** Rejected: decompression
  on attacker-chosen input is a bomb surface, and `max_body_bytes` bounds the
  *compressed* bytes, so the cap would become meaningless.
- **Keep the current behaviour, document it louder.** Rejected: the agent
  controls the request headers, so a louder doc does not close the hole.
- **Reject compressed bodies outright (400) rather than 502.** Rejected: 400
  tells the agent "you compressed a body", which is stage information the
  uniform-502 contract exists to withhold.

## Proposal 5: Run the registry-aware validation on boot and on hot reload

### Problem
Postern has two validation passes. The schema pass checks YAML shape. The
registry-aware pass (`config.ValidateProviders`) checks the things only the
credential registry can answer: is this provider name registered, are these
ref schemes routable, is this unqualified scheme ambiguous, do these
credentials resolve to a configured credstore.

Today that second pass runs in exactly one place: `postern config validate`.
Neither `postern server` nor the hot-reload watcher runs it. Both take the
schema-only path, so:

- A hot-reloaded config naming a credstore that does not exist, or using an
  ambiguous unqualified scheme, is accepted, logged as "config reload
  applied", and then 502s every request it matches.
- Boot-time failures that validation *could* report with a line number
  ("unknown provider", "unroutable ref") arrive as bare Go errors instead.
- `postern config validate` itself has a gap: route refs never get the scheme
  check, so `routes:` with a bad scheme passes validate and then fails boot.

The machinery to fix all three already exists. `newProviderFacts` is sitting in
internal/cli/server.go:530, unused by the two paths that need it.

### Evidence
- internal/config/loader.go:80-82 — `if factsFn != nil { ValidateProviders(...) }`.
  A nil `factsFn` silently skips the whole registry-aware stage.
- internal/cli/config.go:70 — the **only** non-test caller passing a
  `factsFn`: `config.LoadFileWithProviders(target, newProviderFacts(reg))`, i.e.
  `postern config validate` alone.
- internal/config/watcher.go:258 — hot reload: `cfg, lints, err := LoadFile(w.path)`.
  Schema-only. No provider facts reach the reloader.
- internal/cli/server.go:221 — server boot: `cfg, err := config.LoadForCLI(cfgPath, required)`,
  which resolves to `LoadFile` at internal/config/loader.go:149-153.
- internal/cli/rules.go:48 — third schema-only caller, for the same reason.
- internal/config/providers.go:104-117 — `checkRefScheme` runs for
  `rules[i].secret_ref` and the four oauth1 refs. It does **not** run for route
  refs; providers.go:129-131 gives those only `checkQualifiedRef`.
- internal/config/validator_credstore.go:52-53 — the comment `case 0: // No
  credstore at all: already flagged by checkRefScheme` is therefore false for
  route refs: nothing flagged them.
- internal/cli/server.go:464 (`credstore %q: unknown provider %q`) and
  internal/cli/server.go:481-519 (`assertRulesRoutable`) are the runtime
  substitutes — correct, but line-number-free and, in the reload case, too late.
- internal/cli/server.go:530 — `newProviderFacts(reg)` already builds exactly
  what both callers need.
- internal/config/watcher.go cannot import `credstore` (credstore imports
  broker, broker imports config), so the fix is dependency injection, not a new
  import: thread a `ProviderFactsFunc` into the watcher from the CLI.

### Acceptance criteria
- [ ] `postern server` loads through the registry-aware pass, so an unknown
  provider, an unroutable ref, and an ambiguous unqualified scheme fail boot with
  a **line-numbered** lint instead of a bare Go error — and `postern config
  validate` reports the identical set for the identical file.
- [ ] The hot-reload watcher runs the same pass. A reload that would introduce
  an unroutable or ambiguous ref is rejected as a fatal lint and the previous
  ruleset keeps serving, exactly as the existing empty-ruleset guard
  (internal/broker/reloader.go:133) already behaves.
- [ ] `rules[*].routes[*].secret_ref` gets `checkRefScheme`, and
  `checkQualifiedRef`'s `case 0` stays silent so a rule-level ref is not
  double-linted.
- [ ] The provider facts function is injected, not reimplemented: no scheme or
  credstore routing logic is duplicated into `config` or `broker`.
- [ ] `postern rules list` gains the same pass, so the command an operator runs
  to inspect a config agrees with the one they run to validate it.
- [ ] Every config that currently boots still boots, with no change to the
  existing config test suite.
- [ ] `internal/cli/server.go:481-519` keeps working as a defence in depth
  backstop; the validation pass moves the failure earlier, it does not remove it.

### Alternatives considered
- **Add line numbers to the boot errors.** Rejected: the line data lives in the
  YAML AST that the boot path discards at load time. Running the pass that
  already has the AST is strictly cheaper.
- **Move ref-scheme validation into `broker.FromConfigRules`.** Rejected: it
  would duplicate the routing picture in a second place and let the two drift.
- **Make `postern config validate` the only gate and tell operators to run it.**
  Rejected: it cannot cover a hot reload, which is the case that hurts most.

## Proposal 6: `postern rules explain` — answer a hypothetical request offline

### Problem
There is no way to ask postern what it would do with a given request.

`rules list` is config-shaped: it reads the file and prints rows. It cannot
answer the question an operator actually has — "my agent called
`POST api.example.com/v1/messages` and no key went in; which rule matched,
did the path match its scope, which credstore would it resolve from, which
header would it inject?" — without starting the proxy, turning logs up to
`debug`, and reproducing the call.

The three scoping features shipped in 0.9.0 (`paths`/`methods`, `routes`,
credstore-qualified refs) are all **invisible** in every existing output. An
agent cannot self-diagnose its own configuration either, because no
introspection surface exists at all.

### Evidence
- internal/cli/rules.go:30 — `cmd.AddCommand(newRulesListCmd(reg))` is the only
  subcommand registered on the `rules` verb.
- internal/broker/engine.go:23-33 — `Match(host) (Rule, bool)` is the whole
  decision, host-only, first-match-wins, over an `atomic.Pointer` ruleset.
- internal/broker/rule.go:66-72 and internal/broker/scoping.go:28-40 —
  `SelectRoute` and `scopeAllows` are the remaining two stages, both pure
  functions of `*http.Request` plus a `Rule`.
- internal/broker/engine.go:45-47 — `Len()` already exists, so the command can
  report "this config has 12 rules; none matched" instead of an empty table.
- internal/cli/rules.go:129-135 — the existing no-resolve boundary is written
  down and load-bearing: "The CLI cannot resolve credentials anyway (no token
  chain runs here) — this constraint is documented so future refactors don't add
  a 'resolve and show' convenience that would defeat the trust boundary."
- `grep` for `explain|doctor|diagnose|dry.run|simulate|whatif` across
  `internal/`, `cmd/`, `docs/`, and `README.md` returns no implementation.

### Acceptance criteria
- [ ] `postern rules explain --host H [--path P] [--method M] [--route-token T]`
  prints the rule that would match, the resolved credstore and provider, the
  inject type/name/template, and the outcome at every stage: host match, path
  scope, method scope, route selection.
- [ ] It reports the terminal outcome the proxy would produce — injected,
  scoped out, no route token, ambiguous, would-fail-closed — without starting
  the proxy and without reading the config file from anywhere else.
- [ ] It never resolves a credential, never prints a route token, and never
  prints a resolved value: the internal/cli/rules.go:129-135 boundary is
  preserved and a test asserts it against a credential-bearing fixture.
- [ ] No admin-listener route is added. An explainer reachable over a network
  socket would itself be the oracle the uniform-502 contract exists to prevent.
- [ ] With no host/path/method flags it prints the ruleset version and rule
  count, so an operator can confirm a hot reload landed.
- [ ] `--format json` matches the existing `rules list --format json` contract
  (internal/cli/rules.go:81) so the two are scriptable together.
- [ ] A config with zero matching rules says so, and names the count of rules
  that were considered.
- [ ] An unroutable ref is reported as such rather than silently omitted —
  reusing the provider facts from Proposal 5 rather than a second routing model.

### Alternatives considered
- **Extend `rules list --format json` instead.** Rejected: the question is
  request-shaped, not row-shaped; bolting a synthetic row onto a listing makes
  both worse.
- **Expose it on `GET /healthz`.** Rejected: that turns a local diagnostic into
  a network-reachable oracle disclosing which hosts are brokered.
- **A general `postern doctor`.** Rejected as the first move: too broad to land
  and review. `explain` is the piece operators reach for most.

---

# Ranked backlog (proposals 7+)

Everything below is a real gap with a verified pointer. Ranked by
user-observable value x ease. None of it is a proposal until it is picked up;
several fold into the three above.

| # | Gap | Evidence | Size |
|---|---|---|---|
| 1 | No request-path telemetry at all. `/healthz` carries three fields; there is no counter, gauge, or histogram anywhere in the module, cache hits log at Debug, and the per-request summary line carries no rule, no route, and no duration. "Which of my 12 rules is failing?" is unanswerable. | internal/runtime/admin.go:28-32, internal/credstore/cache.go:177 | M |
| 2 | Broker failure lines cannot be joined to the request that produced them — the hook receives only `*http.Request`, never `*goproxy.ProxyCtx`, so `session` (logged by the proxy) is structurally unreachable from all 15 broker log sites. | internal/broker/hook.go:62, internal/broker/hook.go:163-168, internal/proxy/handler.go:203 | S |
| 3 | Log level is immutable. The level is a `slog.Level` value baked into the handler at construction; there is no `slog.LevelVar` and SIGHUP is not in the signal set. An operator cannot escalate to `debug` during a 502 storm without a restart that force-closes live tunnels. | internal/logging/logging.go:62, :66, :82-95; internal/cli/server.go:68 | S |
| 4 | `postern token set` ignores `keychain_account` entirely. Every token subcommand uses a hard-coded `"default"`, while the server honours the config field — so `token set` can store a token the server will never read, and `token status` reports it healthy. | cmd/postern/main.go:111-114, internal/token/resolve.go:41 | S |
| 5 | `ca.Load` checks nothing but the key file mode. No expiry check, no key-to-cert correspondence, no self-signature check. **[reproduced]** An 11-year-old CA loads without error and mints leaves whose `NotAfter` is the CA's `NotAfter` — a year in the past. Every brokered handshake then fails with an opaque TLS error while `/healthz` reports `ok`. | internal/ca/gen.go:147-185, internal/ca/mint.go:149-151 | S |
| 6 | No way to invalidate the credential cache. A vault-side rotation is not noticed until the entry passes `refresh_ahead` (45 minutes at defaults); there is no CLI verb, no admin route, no SIGHUP, and hot reload never touches the cache. | internal/credstore/cache.go:174-180, internal/runtime/admin.go:76 | S-M |
| 7 | `postern config validate` cannot see the token chain. The `token:` block is never schema-validated, so an unknown `source:`, an unset `env_var`, or a `file:` path that does not exist passes CI and fails at boot with no line number. | internal/config/validator.go:197-233, internal/token/resolve.go:52 | S |
| 8 | Self-loop risk: the upstream transport sets `Proxy: http.ProxyFromEnvironment`, and the documented workflow is `eval "$(postern bootstrap)"` in the same shell. An operator who exports `HTTPS_PROXY` before starting postern makes every upstream call re-enter postern through itself. Current behaviour is pinned by a test, so this needs a decision, not a drive-by. | internal/proxy/proxy.go:209, internal/cli/bootstrap.go:111-112 | S |
| 9 | `on_no_match: block` answers CONNECT refusals with a distinctive body, `"blocked by postern: host not brokered"`, letting an agent fingerprint rule-set membership per host — the differential `failClosedBody` exists to remove. Judgment call: `block` is an opt-in allowlist, and the body is genuinely more debuggable. Keep the log informative, make the wire constant. | internal/proxy/proxy.go:145 | S |
| 10 | No credential-cache invalidation or introspection for the long-lived service-account token either: it is resolved once at boot and never re-resolved, so a vendor-side SA-token rotation 502s every brokered request until someone restarts the process. | internal/cli/server.go:221, :412-424 | M |
| 11 | `token set` / `token test` validate against 1Password only, regardless of the configured provider, and print "Validated against credential vendor" naming no vendor. The CLI is strictly less accurate than the runtime it fronts. | cmd/postern/main.go:30-39, internal/cli/token.go:74 | M |
| 12 | Exit codes are 0/1/2. "config is broken", "vault rejected the token", and "platform unsupported" are indistinguishable to a script, despite the sentinel errors already existing for each. | cmd/postern/main.go:116-124, internal/ca/trust.go:30 | S |
| 13 | Machine-readable output exists in exactly one place. `config validate`, `token status`, `ca install`/`uninstall`, and `server healthcheck` are prose; only `rules list --format json` and `/healthz` are structured. | internal/cli/rules.go:81, internal/cli/config.go:76-85 | S-M |
| 14 | Rule selection is host-only, so "different credential for a different path or method on the same host" is inexpressible. `Match` returns the first host hit, `paths`/`methods` are a filter that 502s rather than falls through, and duplicate hosts are a fatal lint. | internal/broker/engine.go:26-31, internal/config/validator.go:245 | M |
| 15 | Unbounded vendor fan-out on non-cacheable refs. The `ShouldCache == false` branch bypasses both the cache and the singleflight group with no concurrency limit, so N concurrent requests mean N concurrent vault calls — and both OTP refs and every `oauth2` ref take that branch by design. | internal/credstore/cache.go:158-166, internal/credstore/oauth2/provider.go:52 | S |
| 16 | The MITM `tls.Config` advertises no ALPN, so every brokered connection negotiates HTTP/1.1 — gRPC and h2-refusing clients cannot be brokered at all. Verify goproxy's MITM server is h2-capable **before** adding `NextProtos`; doing it blind would break every brokered request. | internal/proxy/proxy.go:251-262, internal/proxy/proxy.go:214 | S? |
| 17 | WebSocket upgrade on a brokered host has no code path and no test — only an honest note in the security doc that it "is not yet handled". | docs/security.md:220 | ? |
| 18 | The admin listener's loopback guarantee is enforced once, not "twice over" as documented. The only check is in config validation; `runtime.New` binds whatever address it is handed. | docs/security.md:174, internal/runtime/runtime.go:204-206 | S |
| 19 | `oauth2` credstores using the refresh grant skip the boot ping entirely and return `nil`, so `/healthz` reports them permanently `ok` and a dead IdP surfaces as a first-request 502. Directly contradicts the boot-validation guarantee. | internal/credstore/oauth2/provider.go:97-99, docs/security.md:164 | M |
| 20 | Rule counts are uncapped and `Match` is a linear scan run twice per CONNECT (once for interception, once per in-tunnel request). At a few thousand rules the tail is unreachable in practice. | internal/broker/engine.go:26-31, internal/cli/server.go:312 | M |
| 21 | A glob and a literal host under it can silently shadow: dedup is byte-equality only, and first-match-wins means a wildcard listed first steals every literal beneath it. | internal/config/validator.go:244-250, internal/broker/engine.go:26-31 | S |
| 22 | `install.sh` verifies integrity but not authenticity: `checksums.txt` is fetched from the same origin as the tarball, and the cosign bundle the release publishes is never fetched. The script also takes no arguments at all — `sh install.sh --help` installs. | install.sh:60-74 | M |
| 23 | No `ca export`. The compose bootstrap writes a trust anchor into the CA volume that the distroless image has no tool to consume, so containerized agents hand-copy a PEM out of a bind mount. `postern ca` is `install` and `uninstall` and nothing else. | internal/cli/ca.go:29-30, docker-compose.yml:20-31 | M |
| 24 | `make ci` does not run the e2e suite, and there is no Makefile target that does — a contributor following `CONTRIBUTING.md` exactly never runs those tests. | Makefile:71-72, test/e2e/main_test.go:1 | S |
| 25 | Shipped behaviour has no e2e coverage: `/healthz`, streaming responses, multi-credstore routing, placeholder routing, and `paths`/`methods` scoping. Four e2e tests exist, all one oauth2 credstore and one header-injection rule. | test/e2e/e2e_test.go:22,66,94,114; test/e2e/helpers_test.go:261-285 | M |
| 26 | The compose example tells the operator to create `op_token` and `config.yaml` in the repo root, and `.gitignore` covers neither. | docker-compose.yml:67, :56, .gitignore:1-34 | S |
| 27 | Linux `ca install` prints "You can now point HTTPS_PROXY at postern" without running `update-ca-certificates --user`, so the CA is not in any trust bundle. The remediation lives only in the doc. | internal/ca/trust_linux.go:32-35, internal/cli/ca.go:55-57 | S |
| 28 | `server --daemon` re-execs a setsid child with `Stdout = Stderr = nil`, prints the pid once, and exits. No pidfile, no log destination, no `stop` counterpart. | internal/cli/server.go:608-631 | S-M |
| 29 | The `bws`-missing error sends the operator to `install.sh` (installs postern, not `bws`) or a `postern -bitwarden` image that does not exist. | internal/credstore/bitwarden/runner.go:43, docs/providers.md:261-263 | S |
| 30 | No package-manager distribution. No Homebrew formula, no winget, no deb/rpm — the `curl \| sh` one-liner is the only documented path. | .goreleaser.yaml (no `nfpms`/`brews`/`winget`/`scoop`/`chocolatey` blocks), README.md:94-99 | S (brew) |
| 31 | In-flight credential resolves are neither drained nor cancelled at shutdown. `Runtime` holds no reference to the resolver and `CachedResolver` has no `Close`, so a SIGTERM kills a vault call mid-flight — sharpest for `oauth2` with `refresh_token_path`, which fails closed when a rotated token cannot be persisted. | internal/runtime/runtime.go:288-302, internal/credstore/cache.go:261 | M |
| 32 | `isSensitive` is a deny-list that misses `apikey` and `api_key` (no `-`, no matching prefix or suffix). Bounded: injection happens after request logging, so only agent-supplied values under an unlisted header name are exposed. | internal/proxy/handler.go:231-250 | S |
| 33 | **SHIPPED.** Upstream responses used to be forwarded byte-for-byte, so an upstream echoing the injected credential handed it to the agent — the one remaining way the credential escaped postern. postern now scrubs the credential out of the response on the way back: a header value carrying it is dropped whole, a trailer value carrying it is dropped at end of stream (Go fills `Response.Trailer` only at EOF, so that pass has to happen there, and HTTP/2 can install a fresh trailer map after the body was wrapped), and body occurrences are replaced with `<redacted>` by a streaming transform — incremental delivery and flushes preserved, never buffered. Percent-escaped forms of the credential are matched with hex case folded, since percent-decoding ignores it; the raw credential is matched byte-for-byte so a credential containing a literal percent sequence is not confused with its decoded form. A response still compressed in an encoding the transport did not decode fails closed with `502` rather than being forwarded, because the credential is unreachable inside it. `HEAD` / `101` responses are left alone because wrapping either breaks framing, so a `101` tunnel's frames are the one residual reflection path; it is now logged rather than silent. Opt out with `proxy.scrub_responses: false`. This closes the last of the proxy-gateway model's stated strengths that postern previously did not implement. | `internal/proxy/scrub.go`, `internal/broker/injected.go`, `proxy.scrub_responses` in `docs/configuration.md` | M |

---

# Documentation-truth gaps (no code change)

Every item here is a claim the docs make that the code does not honour, or the
reverse. Each is a small patch and each currently costs a reader a wrong
decision. Line citations were re-verified against the post-#105 tree — several
had drifted when earlier restructuring moved the text out from under them.

- `docs/architecture.md:148-152` promises a hot-reload drift warning for
  "Listener, cache, admin-listener, and token settings". `warnDriftedFields`
  covers cache_ttl, cache, listen, on_no_match, max_body_bytes, scrub_responses
  and credstores — **not `admin_listen`** (internal/broker/reloader.go:166-210).
  Editing the admin port logs "config reload applied" and does nothing.
- `docs/security.md:174` says loopback-only is "enforced twice over". It is
  enforced once, at config validation.
- `docs/security.md:164` promises a boot-time ping for every credstore. The
  oauth2 refresh grant returns `nil` instead (internal/credstore/oauth2/provider.go:97-99).
- `docs/configuration.md:124` says `config validate` requires an explicit ttl.
  That requirement lives only in the `p.Cache == nil` branch
  (internal/config/validator.go:151-155), so a `cache:` block carrying only
  `refresh_ahead` validates clean and silently inherits the 1h default.
- `docs/providers.md:396` says postern "supports exactly one credstore per
  provider today" and that two `oauth2` entries fail at boot. That shipped in
  0.9.0 (Proposal 2); the name-keyed router handles it
  (internal/credstore/router.go:43-77).
- `internal/config/default.yaml:126` — the file `config init` writes into every
  user's home — says the oauth2 authority "selects the credstore by name". It
  does not: the authority is a reserved label and is uninterpreted
  (internal/credstore/oauth2/resolver.go:40-41), and two IdPs are selected by
  credstore name. `docs/providers.md:342` now states this correctly, so the gap
  is the shipped config file alone.
- `docs/providers.md:455` documents a `-tags bitwarden` CI compile gate as the
  model for experimental providers. No file in
  internal/credstore/bitwarden/ carries a `//go:build` line, so the gate
  compiles the same tree as the default build.
- The README said postern fetches secrets from "1Password or Bitwarden" and
  omitted the OAuth2 provider entirely, despite it shipping since 0.5.0.
  **Fixed after `ca04acb`**: the README now leads with the two credential
  sources and names `oauth2://` explicitly.
- `README.md:140` says `rules list` shows "host and `secret_ref`" and that
  "routes, `injects`, and OAuth1 references are not listed". It emits six
  columns and derives the CREDSTORE column from route refs and all four oauth1
  refs (internal/cli/rules.go:92-118, :137-158).
- `CHANGELOG.md:60` records goproxy held "at 1.8.4 to keep streaming
  unbuffered"; go.mod:8 pins v1.9.2, and no release entry records the bump.
- Undocumented but shipped: `postern server --daemon`, `rules list --format
  json`, `config init --force`, `token status|test|rm`, `bootstrap --shell fish`,
  `--log-level quiet`, the `NO_COLOR` ladder, and 1Password OTP refs (the
  `?attribute=otp` grammar, which `ShouldCache` honours and no doc mentions).

# Already tracked in GitHub

Not duplicated here: issue #22 (break the config-to-credstore import cycle),
#24 (config/test structural follow-ups), #27 (regression guards for fail-closed,
no-secret-logged, and the cache race). None overlaps Proposals 4-6.
