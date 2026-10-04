# CB4A alignment

This document records how postern relates to CB4A, what it borrows, and where
it deliberately differs. It is written so a reader can check every claim: each
row points at the postern source that backs it.

## What CB4A is — and what it is not

CB4A ("Credential Broker for Agents") was an **IETF Internet-Draft**:
`draft-hartman-credential-broker-4-agents-00`, authored by K. Hartman (SANS
Institute), published 2026-03-29, declared **Informational**, and **expired
2026-09-30**. The datatracker records it as "Expired & archived"; as of
2026-10-03 no `-01` revision exists and the draft has "no formal standing in the
IETF standards process".

Read that again: **it expired, it was never endorsed by the IETF, and its own
boilerplate says it is not to be cited as normative standards-track material.**
Nothing in this document is a conformance claim, and postern does not claim one.
What follows is a comparison against one author's architectural opinion,
recorded because its vocabulary is useful when designing a broker — not because
anyone ratified the names.

### How to read this

- CB4A is **an expired draft by one author**, not a consensus document, and it
  may never be revised. Treat it as one serious opinion about credential
  brokering for agents, useful because it names the trade-offs crisply — not
  because anyone has ratified the names, and not because it is current.
- **The section numbers below refer to the `-00` revision.** If the author
  revises, every citation here needs re-checking; nothing in this file should be
  treated as a stable reference.
- Where postern agrees, the point is usually that **postern already did the
  thing** and CB4A gives it a name worth using in a design review.
- Where postern differs, the difference is recorded in
  [Known deviations](#known-deviations) rather than papered over. Nothing here
  is compliance theatre: of the three models postern **partially implements
  one** (Model A, with one named gap), **does not implement** Models B or C,
  and of the seven statements below it **meets one** (§4.3), **violates two**
  (TM-9 — the fail-open described below; §2.1 — no policy/credential split),
  **meets one only in part** (§4.4, by design), and leaves **three**
  unaddressed.
- Section numbers refer to the `-00` revision. If the author revises the draft,
  every citation here needs re-checking.

## The three CB4A models vs. postern

CB4A §3 defines three credential proxy models. Postern partially implements the
first; there is no path in the tree to the second or the third.

| CB4A model | Draft's description | Postern verdict | Evidence |
|---|---|---|---|
| **Model A — Proxy Gateway** (§3.1) | The agent never receives, sees, or holds the real credential; the broker injects it and forwards. Works with any target API, including ones that cannot mint short-lived credentials. | **Implements, with one gap** | TLS interception and injection: `internal/proxy/proxy.go:62` (`ShouldIntercept`), `internal/broker/hook.go:63` (the match → resolve → inject hook). The agent holds only what it sent. Response filtering — the draft's "inspect, log, and filter every request **and response**" — is implemented: `internal/proxy/scrub.go` strips the injected credential from the response on the way back, streaming, with `proxy.scrub_responses` as the opt-out. One clause remains unmet: the draft says the broker "validates the agent's session token", and postern authenticates nobody. |
| **Model B — Short-Lived Token Minting** (§3.2) | The broker mints a short-lived token "with narrow scope, then **hands that short-lived token to the agent**. The agent uses the short-lived token to call the target service **directly**." The draft's recommended primary model. | **Does not implement** | The delivery half is absent: every credential postern resolves is injected into a request travelling *through* postern (`internal/broker/hook.go:161` and `:228`, both followed by `Inject` and a `return nil` that forwards), and the only agent-facing surface is `GET /healthz` on a loopback listener (`internal/runtime/admin.go:75-77`). The agent never receives the token. What postern *does* have is Model B's **credential-sourcing** half: the `oauth2` provider mints short-lived bearer tokens and injects them (`internal/credstore/oauth2/provider.go:28`, registered by default at `internal/cli/server.go:28`). That is Model A's delivery with a different credential's provenance — a real improvement over holding a long-lived key, but not the model the draft describes. Nor is it generic: `grant_type` accepts only `client_credentials` and `refresh_token` (`internal/credstore/oauth2/provider.go:212`), so RFC 8693 token exchange and RFC 7523 JWT-bearer assertion — the draft's generic mechanism and the one GitHub App installation tokens need — are both absent. |
| **Model C — Credential Wrapping with Scheduled Revocation** (§3.3) | Hand the agent a wrapped, time-limited credential; weakest isolation; for targets that support only long-lived credentials. | **Does not implement** | No wrapping, unwrapping, or schedule-revocation code exists. The injection surface is a fixed set of typed fields — `internal/config/schema.go:264-298` — with no envelope type. |

**One delivery model, two credential sources.** A rule's `secret_ref` scheme
selects the provider: a vault-backed rule brokers a stored secret, an
`oauth2://` rule brokers a freshly minted short-lived access token. In both
cases the request still traverses postern, and postern is still the thing the
agent's traffic depends on — the extra network hop and the single-point-of-
failure the draft names as Model A weaknesses apply equally to both.

**What the IdP path actually buys.** The access token postern injects expires
on the IdP's schedule rather than living until a human rotates a key, so a
leaked agent never yields a durable credential for that upstream. Three limits
are worth stating plainly, because they are easy to over-read:

- The token **is** cached in postern's memory — the `x/oauth2` `TokenSource`
  holds it until expiry by design (`internal/credstore/oauth2/resolver.go:6-8`,
  `:64-65`). `ShouldCache` returning false (`internal/credstore/oauth2/provider.go:48`)
  bypasses postern's *own* broker cache and nothing else. A test pins the reuse
  (`internal/credstore/oauth2/resolver_test.go:165`).
- The **IdP client secret is long-lived and lives in the process** for its
  whole lifetime, and under `grant_type: refresh_token` a durable refresh token
  is held in memory *and written to disk* at `refresh_token_path`
  (`internal/credstore/oauth2/resolver.go`, `writeRefreshTokenFile`).
- Therefore a **compromised postern is not protected** by choosing this path.
  It holds the client secret and can mint indefinitely. What shrinks is the
  window an *agent* can be tricked into leaking, not the blast radius of the
  broker itself.

## Normative statements the draft makes, and postern's status

These are the draft's `MUST` / `SHOULD` statements that touch postern's
behaviour. "Meets" means postern's shipped behaviour matches the statement as
written; it is **not** a conformance claim, because an Informational draft
licenses no conformance.

| Draft statement | Postern status | Evidence |
|---|---|---|
| §7 (TM-9): "CB4A MUST NOT default to fail-open under any failure condition." | **Violated — one known fail-open path.** See the TM-9 row in the threat table and [Proposal 4](proposals.md#proposal-4-fail-closed-on-a-request-postern-cannot-inject-into). | The invariant is stated at `internal/broker/hook.go:55-58` and every resolve/inject error honours it via the uniform 502 (`internal/broker/hook.go:284`, `:293`), with guards that run before the resolver (`internal/broker/hook.go:87` scoping, `internal/broker/hook.go:104` cleartext refusal). **But** a placeholder rule whose only surface is `body`, meeting a request with a non-identity `Content-Encoding` or a `multipart/*` type, resolves the real credential, injects it nowhere, and forwards the request to the brokered upstream **unauthenticated** — `internal/broker/inject.go:219-220` documents the behaviour deliberately, and `internal/broker/inject.go:291-294` is the mechanism (the `ErrNoPlaceholder` guard is `eligible > 0`, and a skipped body never increments `eligible`). The agent controls its own request headers. **The request is also logged at `info` as `broker injected`** (`internal/broker/hook.go:254`) — the hook reaches that line whenever `Inject` returns nil, which for this path means nothing was injected — so the audit trail records a successful injection for a call that carried no credential. Two scope limits, so the row is not over-read: it is reachable **only** for a rule whose sole declared surface is `body` (a header-injection rule, the common case, is unaffected), and an operator can close it today by declaring a second injection surface, because any second eligible surface makes the rule fail closed. That is a workaround, not a fix. |
| §7 (TM-3): "DPoP sender-constrained tokens (RFC9449) MUST be used to prevent replay." | **Not implemented.** No DPoP, SPKI binding, or PKCE anywhere in the tree. The token requests are plain client-authenticated HTTP. | `internal/credstore/oauth2/resolver.go:97-115` builds the token source with no proof-of-possession parameter, and the provider's settings grammar is a closed key set (`internal/credstore/oauth2/provider.go:178-185`) with no such option. |
| §7 (TM-11): "Broker bypass, where agents access services directly without CB4A mediation, MUST be prevented through network-level enforcement, not agent cooperation." | **Not implemented, and not claimed.** `on_no_match: block` is an allowlist over traffic that reaches the proxy, nothing more. | `internal/config/schema.go:163` defines the field; `internal/broker/hook.go:71` applies it after a request is already inside the proxy; `internal/proxy/proxy.go:67` is the connect-time form. Both are documented as proxy-scoped in [security.md → Egress containment](security.md#egress-containment-with-on_no_match). |
| §4.4: "The CDP MUST NOT cache decrypted credentials in memory beyond the minting operation … immediately zeroed." | **Partially met on the IdP path, deliberately not on the vault path — see [Known deviations](#known-deviations).** | The IdP path is closer to the statement: the access token bypasses postern's broker cache (`internal/credstore/oauth2/provider.go:48` returns `false` from `ShouldCache`, so `internal/credstore/cache.go` never holds it). But it is not zeroed — the `x/oauth2` `TokenSource` keeps it in process memory until expiry (`internal/credstore/oauth2/resolver.go:6-8`, `:64-65`), and the IdP client secret is long-lived and resident for the process lifetime. The vault path deliberately does the opposite: postern caches and serves stale on refresh failure, up to `proxy.cache.max_stale` (`internal/credstore/cache.go:180`, defaulting to 24h at `internal/config/schema.go:188`), which is what keeps a transient vault outage from becoming a 502 storm. The trade-off is written up in [security.md → Credential caching](security.md#credential-caching-and-revocation-window). |
| §4.3: "Policy evaluation MUST use a typed, compiled policy language (not string interpolation) … No string concatenation or template rendering in policy evaluation paths." | **Meets, in the sense the sentence intends.** Postern's policy *is* typed data: the rule set is a Go struct compiled once when the ruleset is loaded, and every authorization decision is a field comparison or a string prefix test. | `internal/broker/from_config.go:22` translates `[]config.Rule` into `[]broker.Rule` — the single crossing point; `internal/broker/engine.go:23` (`Engine.Match`) and `internal/broker/rule.go:205` (`Rule.Match`) evaluate the compiled ruleset; `internal/broker/scoping.go:28` (`Rule.scopeAllows`) does the `paths` / `methods` scoping. |
| §4.8: "Implementations SHOULD include anomaly detection on API call patterns, mid-flight kill switches, and behavioral baselines." | **Not implemented.** No metrics endpoint, no baseline model, no mid-flight kill switch. | Per-request visibility exists but is only a log line: `internal/logging/summary.go:29` (`logging.Summary`) emits method/host/status. No `/metrics` handler exists anywhere in `internal/` or `cmd/`. The closest thing to a kill switch is hot-reloading the config file, which is bound to whole-process policy, not to one request. |
| §2.1: "The component that decides 'yes' (PDP) MUST never touch credential material. The component that dispenses credentials (CDP) MUST never make policy decisions." | **Violated.** Postern is one process in which the match decision, the resolver, and the injector run in a single hook. | `internal/broker/hook.go:63` returns one closure that performs host match, scope check, resolution, and injection. There is no policy service to authorize against and no separate credential surface to isolate or harden, so compromising either half yields both. This is a structural property of the design, not an oversight — see [Known deviations](#known-deviations). |

### One clarification about the credential template

Postern does have a template string — `template: "Bearer {{ CREDENTIAL }}"` —
and it is worth being explicit that this is **not** a violation of the §4.3
sentence above, because the two things are unrelated. §4.3 governs *policy
evaluation*: deciding **whether** a request may be brokered. Postern's policy
decision is entirely typed and compiled (see the §4.3 row's own evidence). The
`{{ CREDENTIAL }}` template governs *credential rendering*: turning a value
that has already been resolved and authorized into the bytes of one header or
placeholder. The template never sees the request, never selects a rule, and
cannot widen access — by the time it runs, the rule has already matched, the
scope has already allowed the request, and the resolver has already returned
the value. Built-in presets (`internal/templates/templates.go:47`) are a
convenience for authoring rules, resolved at config-load time, not at request
time.

## Threat model

CB4A Appendix A, Table 7 lists 11 threats. These five map onto behaviour postern
actually has. Severity is the draft's.

| Threat | Severity | What it is | Postern's position |
|---|---|---|---|
| **TM-1 Broker compromise** | CRITICAL | An attacker who owns the broker process obtains every credential it brokers. | **Accepted, not mitigated.** Postern holds live credentials in memory by design and runs as one trust principal for all of them; Model B reduces the *duration* and *scope* of a given credential's exposure (short-lived access tokens instead of long-lived keys) but does nothing for a compromised process. Documented in [security.md](security.md) under "A compromised postern process". Running postern as a separate uid from the agent is the operator-side control. |
| **TM-2 Revocation failure** | HIGH | A revoked credential keeps working because something upstream still accepts it. | **Partially mitigated, with a named window.** Postern serves a last-known-good value while refreshes fail, up to `proxy.cache.max_stale` (`internal/credstore/cache.go:180`, default 24h at `internal/config/schema.go:188`). If a credential is revoked *and* the vault is simultaneously unreachable, the old value keeps being injected for that window. Setting `max_stale == ttl` disables stale-serving entirely. On the Model B path there is no such window: `oauth2://` refs are never cached by postern (`internal/credstore/oauth2/provider.go:48`), and token lifetime is bounded by the IdP's own `expires_in`. |
| **TM-6 Multi-agent composition** | HIGH | Several agents sharing one broker compose their permissions into more than any single agent was granted. | **Partially mitigated.** Per-agent attribution exists — a `placeholder` rule with `routes` gives each agent its own token, its own secret, and a `name` surfaced in logs, with allowlist semantics and fail-closed behavior on an unknown or ambiguous token (`internal/config/schema.go:278-283`). What postern lacks is the cross-agent correlation the draft proposes: no baseline, no per-agent rate or volume limits, no way to see that four agents are jointly behaving like one. `paths` / `methods` scoping (`internal/broker/scoping.go:28`) bounds each rule independently but does not compare across rules. |
| **TM-9 Fail-open pressure** | HIGH | Operational pressure to let a request through unauthenticated when brokering fails. | **Violated by one path; structurally guarded everywhere else.** Most of the surface honours it: every resolve or inject error returns the uniform 502 and the upstream is never contacted (`internal/broker/hook.go:55-58`), and there is no configuration flag, env var, or break-glass that turns this off. The exception is a placeholder rule whose only surface is `body` receiving a compressed or `multipart/*` request: the credential is resolved, nothing is injected, and the request is forwarded to the brokered upstream **unauthenticated**. This is not a pressure or an operator choice — it is a missing guard that any agent can trigger with a request header. Detailed in the §7 row above and in [Proposal 4](proposals.md#proposal-4-fail-closed-on-a-request-postern-cannot-inject-into). |
| **TM-11 Broker bypass** | HIGH | An agent reaches a service directly, skipping the broker. | **Not mitigated.** `on_no_match: block` is an allowlist for traffic routed *through* the proxy; anything that bypasses the proxy (raw sockets, an unset `HTTPS_PROXY`, non-HTTP protocols) is unaffected. `internal/config/schema.go:163` and `internal/broker/hook.go:71` are the enforcement points, and both are inside the proxy by construction. The honest answer is a host firewall or an egress policy outside postern; [security.md → Egress containment](security.md#egress-containment-with-on_no_match) says so in the operator's terms. |

## Known deviations

These are real. None is fixed by this document; the point is that they are
written down where someone evaluating postern will find them.

1. **The Model A credential cache.** CB4A §4.4 forbids holding a decrypted
   credential in memory beyond the minting operation. Postern's vault providers
   do the opposite, deliberately: it is what keeps a transient vault outage
   from becoming a 502 storm. The exposure window is `proxy.cache.max_stale`
   (default 24h) and only opens when a credential is revoked *while* the vault
   is unreachable. Evidence: `internal/credstore/cache.go:180`. The trade-off
   is documented at [security.md → Credential caching and revocation
   window](security.md#credential-caching-and-revocation-window) and tunable at
   [configuration.md → `proxy.cache`](configuration.md#proxycache).
2. **No PDP/CDP separation.** CB4A splits the decision point (may this request
   be brokered?) from the credential delivery point. Postern is a single
   process where the match decision, the resolver, and the injector run in one
   hook (`internal/broker/hook.go:63`). There is no policy service to
   authorize against and no separate surface to harden or isolate.
3. **No human approval.** CB4A describes a Tier-2 posture in which a person
   approves or is notified about an API call. Postern has no approval queue, no
   notification path, and no break-glass: `grep -i approval` over `internal/`
   and `cmd/` returns nothing. Every brokered request is served or 502'd with
   no human in the loop.
4. **No workload identity.** No SPIFFE/SPIRE integration: nothing attests *which
   process* is asking for the credential. Postern brokers on behalf of whoever
   can reach the proxy port; the only per-client distinction is the
   operator-configured `routes` token (`internal/config/schema.go:278-283`),
   which is a shared-secret scheme, not a cryptographic attestation.
5. **`on_no_match` is not network-level enforcement.** It governs only requests
   that reach the proxy. Treating it as broker-bypass prevention — which is
   what TM-11 asks for — would be overstating it; see
   [security.md](security.md#egress-containment-with-on_no_match).
6. **No sender-constrained tokens.** No DPoP (RFC 9449) anywhere, so a stolen
   access token is replayable until it expires. There is **no operator-side
   mitigation available**: the token TTL is the IdP's decision, not a postern
   setting (`internal/credstore/oauth2/provider.go:178-185` is a closed key set
   with no TTL), so a short `expires_in` is a property of the identity provider
   rather than something an operator can configure into postern.

7. ~~**No response filtering.**~~ **Resolved.** This was the third of Model A
   postern did not implement, and the one that mattered most: an upstream that
   reflects the injected credential back used to hand it straight to the agent,
   because responses were streamed unmodified. `internal/proxy/scrub.go` now
   strips the injected credential out of the response on the way back — header
   values carrying it are dropped whole, trailer values carrying it are dropped
   at end of stream, and body occurrences are replaced with `<redacted>` by a
   streaming transform that preserves incremental delivery and never buffers. A
   response still compressed in an encoding the transport did not decode is
   refused with a `502` rather than forwarded, because the credential is
   unreachable inside it. `proxy.scrub_responses` is the opt-out. `HEAD` and
   `101` upgrade responses are deliberately excluded, because wrapping either
   breaks framing rather than protecting anything — so the frames of a `101`
   tunnel remain unscrubbed, which is the one residual reflection path, and postern
   now logs it rather than passing over it in silence. That is the whole of
   Model A's "filter every response" strength; filtering by anything other than
   the brokered credential is not implemented and is not claimed.
8. **No agent authentication.** Model A's first sentence says the broker
   "validates the agent's session token." Postern validates nothing about the
   caller. `proxy.listen` is checked only as `host:port`
   (`internal/config/validator.go:126-133`), so `0.0.0.0:1701` is accepted and
   anything that can reach the port can have credentials brokered for it —
   while the far less sensitive `admin_listen` *is* loopback-enforced
   (`internal/config/validator_admin.go:21-42`). The only per-client
   distinction is the operator-configured `routes` token, which is a
   shared-secret scheme rather than an attestation. Run postern bound to
   loopback, or behind a control that authenticates the caller.
9. **Nowhere near CB4A Tier 1.** The draft's §6.1 "Minimum Viable CB4A"
   requires SPIRE workload identity, a separate policy decision point, a
   credential delivery point, envelope schema and signing, tiered approval, an
   append-only audit trail, non-renewable leases, and canary credentials.
   Postern has none of: no envelopes, no approvals, no leases, no canaries, and
   an audit trail that is slog lines rather than a write-once log
   (`internal/logging/summary.go:29`). Anyone reading postern as "a CB4A
   implementation" should read that list first.

## Related documents

- [architecture.md](architecture.md) — the request lifecycle these models are
  implemented in.
- [providers.md](providers.md) — the Model B provider in full.
- [security.md](security.md) — fail-closed semantics, the caching trade-off,
  and the threat model in postern's own terms.
