# Placeholder-Token Routing (multi-agent, one host)

> **Status: shipped.** This design has been implemented as the `routes:` field on
> `placeholder` rules. The note below is kept for design rationale; the
> authoritative, current reference is
> [configuration.md → Placeholder routing (`routes`)](../configuration.md#placeholder-routing-routes).

## Problem Statement
How might we let 2-10 agents share one postern instance per host, each presenting
its own token, and have that token select which real secret postern injects -- with
no agent ever holding another's credential?

## Recommended Direction
Extend `type: placeholder` rules with a `routes:` list of named entries
`{name, token, secret_ref}`. The token does double duty: it selects the secret AND
is the in-request placeholder that gets replaced by the resolved value. Operator-
opt-in; postern exposes the cross-agent risk and ships guards (overlap rejection,
fail-closed selection, leak-free logging by route name) but does not impose a trust
model. Stays an allowlist by construction -- only enumerated tokens resolve anything,
unknown/ambiguous/zero -> 502, upstream never called.

Chosen over "multiple rules per host" because it is the only shape with a safe place
to attribute each request to an agent (the `name`) without logging the token, which
the operator flagged as required alongside config ergonomics and isolation.

Example:

```yaml
rules:
  - host: api.telegram.org
    inject:
      type: placeholder
      in: [header]
      template: "{{ CREDENTIAL }}"   # agent sends "Authorization: Bearer <token>"
    routes:
      - name: max
        token: tg_max_8Kq2Lp9wZ      # high-entropy; never logged
        secret_ref: op://Agents/telegram-max/token
      - name: john
        token: tg_john_3Rt7Yx1mQ
        secret_ref: op://Agents/telegram-john/token
```

Request: `Authorization: Bearer tg_max_8Kq2Lp9wZ`
  -> host match -> scan surfaces -> exactly one token (max) -> resolve max ref
  -> replace token with real value -> log {host, route:"max"} (never the token).

## Key Assumptions to Validate
- [ ] Every request to the routed host can carry a token on a declared surface
      (test with the real deployment's request shapes; missing token = fail closed).
- [ ] Operators will pick high-entropy tokens when agents are untrusted
      (mitigate: docs + optional low-entropy lint; they own the risk via opt-in).
- [ ] Handful (<=10) scale holds (if it grows, templated-ref hatch, not built now).

## MVP Scope
IN:
- `routes []Route{Name,Token,SecretRef}` on Rule (schema + broker), placeholder mode only.
- Selection: scan declared surfaces; exactly one route token present -> that route;
  zero or multiple distinct tokens -> failClosed 502, resolver never called.
- Inject: replace matched token with resolved cred (reuse `substitute*` helpers).
- Validation (validator.go, line-numbered): routes XOR (secret_ref + inject.name);
  requires type:placeholder; each route secret_ref a valid URI; tokens non-empty,
  unique, AND no token a substring of another; route name non-empty.
- Logging: emit route name + host on inject; NEVER log the token value.
- Hot-reload (FromConfigRules + Swap) and cache (keyed by secret_ref): free, no change.
- TDD tests across validator/from_config/hook: correct token->correct secret,
  unknown->502 + resolver-not-called, ambiguous->502, overlap->validate error,
  token-never-logged assertion. Coverage >=80% broker/config.
- default.yaml + docs note (entropy, fail-closed).

OUT: see Not Doing.

## Not Doing (and Why)
- Templated/dynamic secret_ref (`{{token}}` in path) -- handful scale; interpolating
  agent input into a vault path is the arbitrary-secret-read edge. Documented hatch only.
- `on_no_token: passthrough` toggle -- breaks fail-closed; a footgun.
- Resolving the token itself from a credstore -- overkill for <=10 agents.
- vaultID/multi-vault plumbing -- routes carry the full ref; reserved param stays "".
- Relaxing host-uniqueness -- routes live inside one rule, so the existing check stands.

## Open Questions
- Which surface holds the token in the real deployment (confirms `in:`)?
- Low-entropy token check: warn-only or skip for v1? (lean skip; operator owns the risk)
- Is `name` required (better observability) or optional with a masked-token fallback?
  (current plan: required)
