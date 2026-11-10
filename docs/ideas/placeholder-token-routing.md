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

Unlike multiple rules per host, named routes attribute requests without logging
tokens. Each route keeps the token and credential reference together in config.

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

## Operational constraints
- Every request to a routed host must carry a token on a declared surface.
  A missing token fails closed.
- Use high-entropy tokens when agents are untrusted.
- This design targets a small number of agents per host.

## Design scope
- `routes []Route{Name,Token,SecretRef}` on Rule (schema + broker), placeholder mode only.
- Selection: scan declared surfaces; exactly one route token present -> that route;
  zero or multiple distinct tokens -> failClosed 502, resolver never called.
- Inject: replace matched token with resolved cred (reuse `substitute*` helpers).
- Validation (validator.go, line-numbered): routes XOR (secret_ref + inject.name);
  requires type:placeholder; each route secret_ref a valid URI; tokens non-empty,
  unique, AND no token a substring of another; route name non-empty.
- Logging: emit route name + host on inject; NEVER log the token value.
- Hot-reload (FromConfigRules + Swap) and cache (keyed by secret_ref): free, no change.
- Tests cover correct token-to-secret selection, unknown and ambiguous tokens,
  overlap rejection, and token-free logs.
- Configuration documentation covers token entropy and fail-closed behavior.

## Alternatives excluded
- Templated/dynamic `secret_ref` values interpolate agent input into a vault path
  and risk arbitrary secret reads.
- `on_no_token: passthrough` would break fail-closed behavior.
- Resolving route tokens from a credstore adds complexity for a small number of
  agents.
- Routes carry the full credential reference, so they need no separate vault ID.
- Relaxing host-uniqueness -- routes live inside one rule, so the existing check stands.
