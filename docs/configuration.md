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
  cache_ttl: 5m               # how long a resolved credential is cached
  on_no_match: passthrough    # passthrough | block
  max_body_bytes: 1048576     # body buffering cap for body substitution (1 MiB)
```

| Field | Required | Meaning |
|---|---|---|
| `listen` | yes | `host:port` the proxy binds. Point your agent's `HTTPS_PROXY` at this. |
| `cache_ttl` | yes | Go duration (`5m`, `30s`). Must be greater than zero. How long a resolved credential is cached before re-fetching; one-time-password references are never cached. |
| `on_no_match` | no | What to do when no rule matches. `passthrough` (default) forwards the request unchanged. |
| `max_body_bytes` | no | Cap (in bytes) on how much of a request body postern buffers when a rule rewrites the body (`inject.in` includes `body`). Default 1 MiB when unset or `0`. A larger body is rejected with `413 Request Entity Too Large` and never reaches the upstream. Bound at startup; a hot-reload edit warns and does not take effect (a per-rule `inject.max_body_bytes` override does hot-reload). |

> **Note — `on_no_match: block`.** The value is accepted today but not yet
> enforced: every unmatched request currently passes through regardless. Don't
> rely on it for egress control. See [security.md](security.md).
>
> **Note — `listen`.** `postern bootstrap` reads `proxy.listen` when emitting
> the agent's `HTTPS_PROXY` snippet. `postern server` currently also accepts an
> `--addr` flag (default `127.0.0.1:1701`); aligning the server's bind to
> `proxy.listen` is in progress, so keep the two in sync for now.

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
| `secret_ref` | yes | A `<scheme>://<rest>` URI the matching provider resolves (e.g. `op://VAULT/ITEM/FIELD`). |
| `inject` | yes* | How to attach the resolved credential — see below. |
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
| `type` | `header` sets a named header to the rendered template. `placeholder` substitutes a sentinel token (`name`) already present in the request. |
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
- `inject.type` missing or not `header`/`placeholder`; `name` missing for a
  header injection; `template` missing or carrying no `{{ CREDENTIAL }}`
  placeholder.
- `inject.in` set with `type: header`; an invalid surface name; a `placeholder`
  token with reserved characters when a non-header surface is declared.
- `proxy.max_body_bytes` (or a per-rule `inject.max_body_bytes`) negative; a
  per-rule `max_body_bytes` set without `body` in `inject.in`.
- `cache_ttl` not greater than zero; `listen` missing or not `host:port`.
- A rule present but no credstore configured (set `token:` or `credstores:`).
- Duplicate rule hosts or duplicate credstore names.
