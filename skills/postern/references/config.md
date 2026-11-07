# Postern configuration reference

Postern reads one strict YAML file, by default `~/.postern/config.yaml`.
An unknown field is an error.
`postern config validate` reports `line:column` findings; errors block startup.

## Top level

```yaml
token:        # single legacy 1Password store, or:
credstores:   # one entry per vendor/store
proxy:        # listener, cache, response scrubbing
rules:        # ordered host entries
```

Exactly one of `token:` or `credstores:`.
Setting both is a validation error.
A `token:` block synthesizes a store named `default`.

## Credential source

```yaml
token:
  source: auto                          # auto | file | env | keychain
  env_var: OP_SERVICE_ACCOUNT_TOKEN
  file: ""                              # 0600 token file
  keychain_account: default
```

`auto` tries file, then env, then keychain, and uses the first non-empty result.
Never put the token value itself in the config.

```yaml
credstores:
  - name: vault                # routing key, unique
    provider: 1password        # provider Name, not the URI scheme
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
    settings: {}               # provider-specific, non-secret
```

- `1password`: scheme `op`, reference `op://Vault/Item/field`, no settings keys.
- `bitwarden`: scheme `bw`, reference `bw://<secret-uuid>`.
  Needs the `bws` CLI on `PATH` or `settings.bws_path`; optional `settings.server_url` for self-hosted.
- `oauth2`: scheme `oauth2`, reference `oauth2://<credstore-name>`.
  Required settings: `token_url` (https), `client_id`, `grant_type` (`client_credentials` or `refresh_token`).
  Optional: `scope`, `auth_style` (`basic` or `post`), `refresh_token_path` for a rotated refresh token.
  The client secret goes in `token:`; the refresh grant also needs a `refresh_token:` block as its first-boot seed.

With several stores of one vendor, qualify a reference as `<scheme>+<name>://rest`, for example `op+team://Vault/Item/field`.
An unqualified reference is an error when two stores could serve its scheme.

## Proxy

```yaml
proxy:
  listen: 127.0.0.1:1701
  cache:
    ttl: 1h
    refresh_ahead: 45m
    max_stale: 24h
  on_no_match: passthrough     # passthrough | block
  max_body_bytes: 1048576
  scrub_responses: true
  admin_listen: 127.0.0.1:1702 # loopback only
```

- `listen` is required (`host:port`).
  `postern server` resolves its bind address as `--addr`, then `proxy.listen`, then `127.0.0.1:1701`.
- `cache` is bound at startup; `cache_ttl` is the legacy alias for `cache.ttl` and one of them must be set.
  `refresh_ahead` must be below `ttl`; `max_stale` must be at least `ttl`.
- A previously resolved credential keeps serving up to `max_stale` while refreshes fail; lower it for revocation-sensitive secrets.
- `on_no_match: passthrough` tunnels non-matching hosts untouched.
  `block` rejects the `CONNECT` with a 502 and never contacts the upstream.
  A server started with zero rules is brokerless and applies neither policy, and it does not watch the config file.
- `scrub_responses` (default on) strips the injected credential from upstream responses.
  A compressed response it cannot inspect fails closed with a 502.
- `admin_listen` serves `GET /healthz`; validation accepts only loopback IPs, not hostnames.

## Rules

First matching rule wins.
Hosts are literal names or single-`*` globs matching exactly one label.
Never use a wildcard on a shared or multi-tenant suffix such as `*.s3.amazonaws.com`: any host an attacker can register there would receive the credential.

```yaml
rules:
  - host: api.example.com
    secret_ref: op://Agents/Example/api_key
    paths: ["/v1/"]
    methods: [POST]
    inject:
      type: header
      name: authorization
      template: "Bearer {{ CREDENTIAL }}"
```

- `paths` entries are prefixes compared against the escaped wire path and must start with `/`.
- `methods` entries are case-insensitive tokens.
- A matched request outside the declared scope fails closed with a 502 before the resolver runs.
- `template` must contain `{{ CREDENTIAL }}` or postern refuses to start.

### Placeholder injection

```yaml
    inject:
      type: placeholder
      name: __example_key__
      template: "{{ CREDENTIAL }}"
      in: [header, body, query]
```

The client sends the sentinel; postern replaces every occurrence on the declared surfaces (`header`, `body`, `path`, `query`, default `[header]`).
A non-header surface restricts `name` to RFC 3986 unreserved characters.
Compressed and multipart bodies are skipped.
If the sentinel appears on no eligible surface, the request fails closed.

### Multiple headers and OAuth 1.0a

```yaml
  - host: api.example.com
    secret_ref: op://Agents/Example/api_key
    injects:
      - type: header
        name: authorization
        template: "Bearer {{ CREDENTIAL }}"
      - type: header
        name: x-api-key
        template: "{{ CREDENTIAL }}"
```

`injects` resolves the one `secret_ref` once and feeds every header; entries must be `type: header` with unique names.

```yaml
  - host: api.example.com
    inject:
      type: oauth1
      consumer_key_ref: op://Vault/app/consumer_key
      consumer_secret_ref: op://Vault/app/consumer_secret
      token_ref: op://Vault/user/access_token
      token_secret_ref: op://Vault/user/access_token_secret
```

An `oauth1` rule takes no `secret_ref`, `name`, or `template`.

### Placeholder routing

```yaml
  - host: api.telegram.org
    inject:
      type: placeholder
      in: [header]
      template: "{{ CREDENTIAL }}"
    routes:
      - name: agent-a
        token: tg_agent_a_8Kq2Lp9wZ
        secret_ref: op://Agents/telegram-a/token
```

Each `token` selects which secret resolves and is replaced in place.
Only enumerated tokens resolve anything; a missing or ambiguous token fails closed.
Tokens must be unique, non-overlapping, and high entropy (a low-entropy token only warns).

### Approval

```yaml
    approval:
      ttl: 10m               # 0s or omitted: prompt for every request
      methods: [POST, DELETE]
```

- Nothing resolves and nothing reaches the upstream until the user approves.
- With `ttl: 0s`, every request prompts; with a positive `ttl`, one approval grants the rule and route for that window.
- Methods outside `approval.methods` inject without a prompt, except requests carrying a method-override header.
- A denial, dismissal, timeout, or cooldown returns the uniform 502.
- Linux needs the polkit action (`postern approval policy | sudo tee /usr/share/polkit-1/actions/dev.postern.policy`) and an authentication agent in the desktop session.
- macOS prompts through LocalAuthentication and needs postern in the login session.
  A non-cgo macOS build has no backend and fails closed.
- A denial starts a 30s cooldown; two refused dialogs within 15 minutes suspend prompting; hot reload clears grants.

### Built-in templates

`template:` fills `host` and `inject` defaults; fields set on the rule win.
Names are case-insensitive: `anthropic`, `openai`, `github`, `stripe`, `googleapis`.

```yaml
rules:
  - template: anthropic
    secret_ref: op://Agents/Anthropic/api_key
```

## Validation

`postern config validate` reports line numbers for at least:

- missing or malformed `host` / `secret_ref`;
- an unqualified reference that two credstores could serve;
- missing `inject.type`, header `name`, or the `{{ CREDENTIAL }}` placeholder;
- `oauth1` with rule-level `secret_ref` or header fields, or a missing `*_ref`;
- `inject.in` on a header rule, an invalid surface, or a bad token charset;
- `routes` combined with a rule-level `secret_ref` or `inject.name`, or duplicate/overlapping route tokens;
- `injects` combined with `inject`, `routes`, or `template`, or duplicate header names;
- empty `paths` or `methods` lists, or a path not starting with `/`;
- a null `approval:` block (write `approval: {}`), a negative `ttl`, or an `approval.methods` entry outside the rule's `methods`;
- a rule with no credential source configured, or duplicate rule hosts / credstore names;
- a non-loopback `admin_listen`;
- a cache where `refresh_ahead` is not below `ttl`, or `max_stale` is below `ttl`.

Warnings, which do not block startup: a route token with low estimated entropy, and a credential source with no rules (brokerless mode).

## Hot reload

A running server with at least one rule watches the config file.
A clean parse swaps the ruleset atomically and increments the health `ruleset_version`.
A config with a fatal lint is rejected and the previous ruleset keeps serving.
Listener, cache, `admin_listen`, token, `on_no_match`, `scrub_responses`, and `max_body_bytes` are bound at startup and need a restart.
