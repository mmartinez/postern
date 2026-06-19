# Configuration

Postern reads a single YAML file, by default `~/.postern/config.yaml`. Write a
starter file with `postern config init` and check it with `postern config
validate` (errors are reported with line numbers). Parsing is strict: an unknown
field is an error, not a silently ignored typo.

## Top level

```yaml
token:        # legacy single-vendor form (or use credstores: below)
credstores:   # multi-vendor form
proxy:        # listener + caching
rules:        # host → secret_ref → injection
```

There are two ways to declare where credentials come from, and you use exactly
one of them:

- **Single vendor** — a top-level `token:` block. Postern synthesizes an
  implicit credstore named `default` from it.
- **Multiple vendors** — a `credstores:` list. Omit the top-level `token:`.

Setting both is a validation error.

## `token`

How postern obtains the credential vendor's service-account token.

```yaml
token:
  source: auto                          # auto | keychain | env | file
  env_var: OP_SERVICE_ACCOUNT_TOKEN     # consulted when source is auto or env
  file: ""                              # path to a 0600 token file
  keychain_account: default             # account label in the OS keychain
```

| Field | Meaning |
|---|---|
| `source` | Where to read the token. `auto` tries `file` → `env` → `keychain` in order, using the first non-empty result. |
| `env_var` | Environment variable name read when `source` is `auto` or `env`. |
| `file` | Path to a file containing only the token. Use `0600` permissions; preferred for headless and container deployments. |
| `keychain_account` | Account label used to store/retrieve the token in the OS keychain. |

Never put the token value itself in the config or on a command line. The config
names *where* the token lives, not the token.

## `credstores`

The multi-vendor form. Each entry names a vendor and how to get its token.

```yaml
credstores:
  - name: primary-vault
    provider: 1password           # the provider's registered Name
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
```

| Field | Meaning |
|---|---|
| `name` | Local handle for this credstore. Must be unique. |
| `provider` | The registered **Name** of a provider compiled into the binary (e.g. `1password`). Not the URI scheme. |
| `token` | A `token` block (same fields as above) for this credstore. |

A rule routes to a credstore by the URI scheme of its `secret_ref`. See
[providers.md](providers.md) for the provider contract and the Name-vs-scheme
distinction.

## `proxy`

```yaml
proxy:
  listen: 127.0.0.1:1701     # host:port to listen on
  cache:                      # background-refreshing credential cache
    ttl: 1h                   # nominal freshness window
    refresh_ahead: 45m        # refresh asynchronously once a value reaches this age
    max_stale: 24h            # keep serving a cached value this long if refreshes fail
  on_no_match: passthrough    # passthrough (tunnel, no MITM) | block (reject the CONNECT)
  max_body_bytes: 1048576     # body buffering cap for body substitution (1 MiB)
```

| Field | Required | Meaning |
|---|---|---|
| `listen` | yes | `host:port` the proxy binds. Point your agent's `HTTPS_PROXY` at this. |
| `cache` | no | Credential cache settings (see below). |
| `cache_ttl` | no | **Legacy alias for `cache.ttl`.** Go duration (`5m`, `30s`). Accepted for backward compatibility; prefer the `cache` block. Setting both `cache_ttl` and `cache.ttl` to different values is a config error. |
| `on_no_match` | no | What to do with a `CONNECT` to a host that matches no rule. `passthrough` (default) tunnels the connection untouched — postern does **not** terminate TLS, so the agent reaches the real upstream with the real certificate and only needs to trust the postern CA for brokered hosts. `block` rejects the `CONNECT` with a `502` and never contacts the upstream (allowlist-only egress for proxied traffic). See [security.md](security.md#egress-containment-with-on_no_match). |
| `max_body_bytes` | no | Cap (in bytes) on how much of a request body postern buffers when a rule rewrites the body (`inject.in` includes `body`). Default 1 MiB when unset or `0`. A larger body is rejected with `413 Request Entity Too Large` and never reaches the upstream. Bound at startup; a hot-reload edit warns and does not take effect (a per-rule `inject.max_body_bytes` override does hot-reload). |

### `proxy.cache`

Credential resolution is a background concern: the request/inject path reads
from an in-memory cache keyed by `secret_ref` and essentially never calls the
vault directly. Concurrent misses for the same reference collapse into a single
vault call (single-flight); an entry past its `refresh_ahead` age is refreshed
on a background goroutine while its current value keeps being served; and a
transient vault failure (rate-limit, timeout) keeps serving the last-known-good
value up to `max_stale` instead of failing closed. A reference that was **never**
successfully resolved still fails closed (HTTP 502) — that security guarantee is
unchanged. One-time-password references are never cached.

| Field | Required | Default | Meaning |
|---|---|---|---|
| `ttl` | no | `1h` | Nominal freshness window. Past `ttl` a value is served *stale* (and logged) while a refresh is attempted. |
| `refresh_ahead` | no | 75% of `ttl` | Age at which a request triggers an asynchronous refresh, so the hot path never blocks on the vault and there is no cold window at expiry. Must be greater than zero and less than `ttl`. |
| `max_stale` | no | `24h` | Hard age limit. A value older than `max_stale` is not served: the resolver re-resolves and fails closed on error. Must be `>= ttl`. |

All three are bound at startup; a hot-reload edit warns and does not take effect
(restart `postern` to apply). The defaults are tuned for long-lived API tokens:
the vault is queried at most once per reference per refresh interval, with
exponential backoff (and jitter) after a transient failure so a rate-limited
vault is not re-hammered.

> **Security note.** Serving a cached value when a refresh fails (up to
> `max_stale`) means a credential revoked at the vault can keep being injected
> for that window if the vault is also unreachable for refreshes. Lower
> `max_stale` (or set it equal to `ttl` to disable stale-serving) for
> revocation-sensitive deployments. See [security.md](security.md#credential-caching-and-revocation-window).

> **Note — `listen` and `--addr`.** `postern bootstrap` reads `proxy.listen`
> when emitting the agent's `HTTPS_PROXY` snippet. `postern server` resolves its
> bind address with the precedence **`--addr` flag → `proxy.listen` →
> `127.0.0.1:1701`** (the default): an explicit `--addr` wins, otherwise
> `proxy.listen` is used, otherwise the built-in default. Set `proxy.listen` and
> the two stay aligned automatically.

## `rules`

An ordered list of host-broker entries. The first rule whose host matches an
outbound request wins.

```yaml
rules:
  - host: api.anthropic.com
    secret_ref: op://Agents/Anthropic/api_key
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
```

| Field | Required | Meaning |
|---|---|---|
| `host` | yes* | A literal hostname (`api.example.com`) or a single-`*` glob (`*.example.com`, matching exactly one label). **Do not use a wildcard on a multi-tenant or shared-suffix domain** (e.g. `*.s3.amazonaws.com`, `*.blob.core.windows.net`): any host an attacker can register under that suffix would also match the rule and receive the injected credential. Reserve wildcards for single-tenant domains you control. |
| `secret_ref` | yes | A `<scheme>://<rest>` URI the matching provider resolves (e.g. `op://VAULT/ITEM/FIELD`). Omit when using `routes` (each route carries its own). |
| `inject` | yes* | How to attach the resolved credential — see below. |
| `routes` | no | Placeholder-routing entries: per-token secret selection for a shared host. Mutually exclusive with `secret_ref`/`inject.name`; see below. |
| `template` | no | Name of a built-in preset (see below) that fills in `host` and `inject` defaults. |

\* When `template` is set, `host` and `inject` may be omitted and are filled
from the preset. Any field you do set on the rule overrides the preset.

### `inject`

```yaml
inject:
  type: header                          # header | placeholder
  name: authorization                   # required when type=header
  template: "Bearer {{ CREDENTIAL }}"   # must contain {{ CREDENTIAL }}
```

| Field | Meaning |
|---|---|
| `type` | `header` sets a named header to the rendered template. `placeholder` substitutes a sentinel token (`name`) already present in the request. `oauth1` signs the request with OAuth 1.0a (HMAC-SHA1) and sets the `Authorization: OAuth` header — see below. |
| `name` | For `header`, the header to set. For `placeholder`, the sentinel token to replace. |
| `template` | The rendered credential string. `{{ CREDENTIAL }}` is replaced with the resolved value. Omitting the placeholder is a **fatal error**: the credential would be discarded and the request forwarded unauthenticated, so postern refuses to start. |
| `in` | (`placeholder` only) The request surfaces to substitute, any subset of `header`, `body`, `path`, `query`. Defaults to `[header]`. |
| `max_body_bytes` | (`placeholder` with `in` including `body`) Per-rule override of `proxy.max_body_bytes`. `0` (or unset) inherits the proxy-wide cap. |

### Substitution surfaces (`placeholder` mode)

By default a `placeholder` rule replaces the sentinel token only in header
values. `inject.in` opts the rule into substituting other request surfaces; the
value is percent- or string-encoded per surface so it can never corrupt the
payload or inject structure:

```yaml
rules:
  - host: openrouter.ai
    secret_ref: op://Agents/OpenRouter/api_key
    inject:
      type: placeholder
      name: __openrouter__          # RFC 3986 unreserved chars only (see below)
      template: "{{ CREDENTIAL }}"
      in: [body, query]
```

| Surface | Encoding of the injected value |
|---|---|
| `header` | Raw. A value containing CR or LF is rejected (header-injection guard) and the request fails closed. |
| `path` | `url.PathEscape` — escaped as a single path segment. |
| `query` | `url.QueryEscape` — escaped as a query component. |
| `body` | Chosen by `Content-Type`: `application/json` → JSON string-escaped; `application/x-www-form-urlencoded` → query-escaped; `multipart/*` → **skipped** (forwarded unmodified); anything else → raw. A body with a `Content-Encoding` (compressed) is **skipped** and forwarded unmodified. |

Notes:

- **Token charset.** When any non-header surface is declared, `name` must use
  only RFC 3986 unreserved characters (`A–Z a–z 0–9 - . _ ~`) so its encoded and
  decoded forms are identical and path/query substitution is stable. Header-only
  rules keep the looser charset.
- **Aggregate match.** With several surfaces declared, the token being found on
  any one eligible surface is success. If it is found on none, the request fails
  closed with `502` and the upstream is never contacted. A body that is skipped
  (compressed or multipart) is not an eligible surface — a body-only rule on
  such a body forwards it untouched.
- **Body size.** Bodies are buffered only when `body` is declared; everything
  else streams. See `proxy.max_body_bytes` for the cap and the `413` behavior.
- **WebSocket frames are out of scope.** postern brokers the HTTP request that
  opens a connection; it does not inspect or rewrite WebSocket message frames.

### OAuth 1.0a signing (`oauth1`)

Some APIs authenticate every request with an OAuth 1.0a HMAC-SHA1 signature
rather than a bearer token. `inject.type: oauth1` makes postern compute that
signature and set the `Authorization: OAuth …` header, so the agent sends an
unsigned request and never holds the four secrets.

```yaml
rules:
  - host: api.example.com
    inject:
      type: oauth1
      consumer_key_ref: op://Vault/app/consumer_key
      consumer_secret_ref: op://Vault/app/consumer_secret
      token_ref: op://Vault/user/access_token
      token_secret_ref: op://Vault/user/access_token_secret
```

| Field | Meaning |
|---|---|
| `consumer_key_ref` | secret_ref for the application consumer key. |
| `consumer_secret_ref` | secret_ref for the application consumer secret. |
| `token_ref` | secret_ref for the user access token. |
| `token_secret_ref` | secret_ref for the user access-token secret. |

Notes:

- **No `secret_ref`, `name`, or `template`.** An `oauth1` rule supplies its
  credentials through the four `*_ref` fields; setting the rule-level
  `secret_ref` or the header/template fields is a config error. The four refs use
  any registered scheme (`op://`, `bw://`, …) and are resolved through the normal
  credstore path, so they are cached like any other static secret.
- **What is signed.** The HTTP method, the normalized request URL, the query
  parameters, and — only for an `application/x-www-form-urlencoded` body — the
  form parameters. A JSON or multipart body is forwarded unchanged and not folded
  into the signature (RFC 5849 §3.4.1.3.1).
- **Fail closed.** If any of the four references fails to resolve (or resolves
  empty), the request fails closed with `502` and the upstream is never
  contacted.

### Placeholder routing (`routes`)

A `placeholder` rule can carry a `routes` list instead of a single rule-level
`secret_ref` and `inject.name`. Each route's `token` does double duty: presenting
it on a declared surface both **selects** which secret to resolve and is the
placeholder **replaced** in place by the resolved value. This lets several agents
share one host rule, each presenting its own token.

```yaml
rules:
  - host: api.telegram.org
    inject:
      type: placeholder
      in: [header]
      template: "{{ CREDENTIAL }}"   # agent sends "Authorization: Bearer <token>"
    routes:
      - name: max
        token: tg_max_8Kq2Lp9wZ
        secret_ref: op://Agents/telegram-max/token
      - name: john
        token: tg_john_3Rt7Yx1mQ
        secret_ref: op://Agents/telegram-john/token
```

| Field | Meaning |
|---|---|
| `name` | Operator-facing label for the agent, surfaced in logs. The token value itself is **never** logged. |
| `token` | The placeholder the agent presents; matching it selects this route. Must be unique and non-overlapping across the rule (see below). |
| `secret_ref` | The `<scheme>://<rest>` URI resolved when this route's token matches. |

- **Mutually exclusive** with rule-level `secret_ref` and `inject.name`. `routes`
  requires `type: placeholder`; the shared `inject` block still supplies
  `template`, `in`, and `max_body_bytes`.
- **Allowlist + fail closed.** Only enumerated tokens resolve anything. A request
  carrying no configured token — or two different tokens (ambiguous) — fails
  closed with `502`, and the resolver is never called.
- **Token entropy is load-bearing.** When agents are mutually untrusted, the
  token is effectively the only thing separating one agent's secret from
  another's. Pick high-entropy, unguessable tokens. postern emits a non-fatal
  **warning** for a token whose estimated entropy is below ~64 bits (short or
  low-diversity, e.g. `tgMax`); it does not block boot, since the operator owns
  the trust decision. postern also **rejects** (fatal) tokens that overlap (one
  a substring of another), because substitution matches by substring.
- **Surfaces** behave exactly as above: tokens are scanned for, and replaced on,
  the surfaces named in `inject.in` (default `[header]`), with the same
  per-surface encoding and the non-header charset restriction.
- **Substitution replaces _every_ occurrence on the declared surfaces.** Once a
  route is selected, the resolved credential is spliced in everywhere its token
  appears across those surfaces (e.g. every header value containing it). Do not
  echo a route token into pass-through fields you don't want the credential to
  land in (a duplicated `User-Agent`, a trace header), or the real secret will be
  forwarded there too. This only ever places the agent's _own_ secret in its
  _own_ request to the already-authorized upstream — never another agent's.

### Built-in templates

Naming a `template` lets a rule skip restating the host pattern, header name,
and credential format for a common API:

```yaml
rules:
  - template: anthropic
    secret_ref: op://Agents/Anthropic/api_key
```

Available presets: `anthropic`, `openai`, `github`, `stripe`, `googleapis`.
Names are case-insensitive.

## Validation

`postern config validate` reports findings with `line:column` locations.
Errors block startup. Common errors:

- `host is required` / a host that is neither a literal nor a single-`*` glob.
- `secret_ref` missing or not of the form `<scheme>://<rest>`.
- `inject.type` missing or not `header`/`placeholder`/`oauth1`; `name` missing
  for a header injection; `template` missing or carrying no `{{ CREDENTIAL }}`
  placeholder.
- `inject.type: oauth1` with a rule-level `secret_ref`, or with `inject.name`,
  `inject.template`, or `inject.in` set; or any of the four `*_ref` fields
  missing or not of the form `<scheme>://<rest>`. (The `*_ref` fields are valid
  only with `type: oauth1`.)
- `inject.in` set with `type: header`; an invalid surface name; a `placeholder`
  token with reserved characters when a non-header surface is declared.
- `routes` combined with a rule-level `secret_ref` or `inject.name`; `routes`
  without `type: placeholder`; a route missing `name`, `token`, or a well-formed
  `secret_ref`; duplicate or overlapping route tokens.

Warnings (reported, non-fatal): a route `token` with low estimated entropy
(below ~64 bits) — a guessability hint, not a hard failure.
- `proxy.max_body_bytes` (or a per-rule `inject.max_body_bytes`) negative; a
  per-rule `max_body_bytes` set without `body` in `inject.in`.
- `cache_ttl` not greater than zero (when no `cache` block is set); `cache.ttl`
  and `cache_ttl` set to different values; `cache.refresh_ahead` not less than
  `cache.ttl`; `cache.max_stale` less than `cache.ttl`; `listen` missing or not
  `host:port`.
- A rule present but no credstore configured (set `token:` or `credstores:`).
- Duplicate rule hosts or duplicate credstore names.
