# Credstore providers

A **credstore provider** is the plug-in seam between postern's broker
runtime and a specific credential vendor (1Password Service Accounts,
Bitwarden, HashiCorp Vault, AWS Secrets Manager, ...). The broker
doesn't know how to fetch a secret; it knows it has a YAML-declared
rule whose `secret_ref` looks like `<scheme>://<rest>` and that there
is some provider in the registry that claims that scheme.

This document is the contract a new provider has to satisfy. If you
follow it, you can drop a new credential vendor into postern as a single
new sub-package; the broker, proxy, and CLI do not need to be edited.

## The interface

```go
package credstore

type Provider interface {
    // Name is the human-readable provider identifier surfaced in config
    // (provider: <name>) and in logs. Must be stable across the
    // provider's lifetime and unique within the registry.
    Name() string

    // Scheme is the secret-reference URI prefix (without the "://")
    // this provider claims. Must be lowercase, non-empty, and unique
    // within the registry.
    Scheme() string

    // Validate performs a cheap, read-only sanity ping against the
    // vendor using token. It runs once at boot before any request is
    // brokered; failures fail the proxy closed rather than wait for
    // the first request to surface a bad credential. settings is the
    // credstore's provider-interpreted config map (see "Settings"
    // below); providers that recognize no keys ignore it at runtime.
    Validate(ctx context.Context, token string, settings map[string]string) error

    // ValidateSettings checks the settings map offline — no token, no
    // network call. The `config validate` path calls it so an unknown
    // key or a malformed value is a line-numbered error rather than a
    // silently ignored field or a boot failure. A provider that
    // recognizes no keys errors on any non-empty map and returns nil
    // for an empty or absent one.
    ValidateSettings(settings map[string]string) error

    // ShouldCache reports whether a resolved value for secretRef may be
    // served from the broker cache. Vendors return false for references
    // whose value is inherently short-lived (e.g. a one-time password)
    // so the cache layer re-resolves them on every request.
    ShouldCache(secretRef string) bool

    // NewResolver constructs a broker.Resolver authenticated with
    // token. settings is consumed transiently (parsed into the returned
    // resolver) and never stored on the Provider, which is a
    // process-wide singleton. The caller is responsible for wrapping the
    // result in any cache or metrics decorators before handing it to
    // broker.Hook.
    NewResolver(ctx context.Context, token string, settings map[string]string) (broker.Resolver, error)
}
```

`broker.Resolver` is the single-method consumer interface the broker
calls per request:

```go
type Resolver interface {
    Resolve(ctx context.Context, vaultID, secretRef string) (string, error)
}
```

`vaultID` is reserved for future multi-vault routing and must currently be
the empty string. Implementations should reject a non-empty `vaultID` with a
clear error so a misconfigured caller fails closed.

## Registration

Providers self-register via `init()` against the process-wide registry,
mirroring `database/sql/driver`:

```go
package myvendor

import (
    "github.com/mmartinez/postern/internal/credstore"
)

func init() {
    credstore.Register(NewProvider(/* deps */))
}
```

The registry panics on duplicate Name or Scheme — registration is a
static, boot-time invariant, and silently overriding a previously
registered provider would be a footgun. Pick a scheme that does not
clash with an existing provider in the tree.

To activate the provider, the binary's `main` package needs to import
your provider package as a side effect. The default postern binary
already imports `internal/credstore/onepassword`; gated providers (see
below) get a tagged side-effect import alongside it.

## Layout convention

Every provider lives under `internal/credstore/<name>/`:

```
internal/credstore/
  provider.go              # Provider interface + Registry types
  registry.go              # process-wide registry
  router.go                # SchemeRouter (broker.Resolver dispatcher)
  onepassword/             # production provider (links the SDK)
    provider.go            # implements credstore.Provider
    client.go              # SDK construction + HealthCheck
    sdk_resolver.go        # broker.Resolver backed by the SDK
    cache.go               # LRU+TTL cache (provider-shared utility)
  bitwarden/               # production provider (shells out to the bws CLI)
    doc.go                 # package doc
    provider.go            # implements credstore.Provider
    runner.go              # narrow exec seam around bws
    settings.go            # parses server_url / bws_path settings
    resolver.go            # broker.Resolver that runs `bws secret get`
    live_test.go           # opt-in live test (BWS_E2E=1)
```

A provider sub-package owns its SDK or CLI shell-out. The only public
surface back to the rest of postern is the `Provider` interface and
whatever its `NewResolver` returns.

## Config

Once a provider is registered, an operator declares one or more
credstores in the YAML config. The `provider:` field is the registered
**Name** of the provider (the string returned by `Provider.Name()`),
**not** the URI scheme. For the production provider:

```yaml
credstores:
  - name: primary-vault
    provider: 1password
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN
```

> ⚠ The Provider's **Name** ("1password") and **Scheme** ("op") are
> distinct on purpose. `provider:` references the Name; `secret_ref:`
> uses the Scheme. Mixing them up surfaces as `unknown provider "op"`
> at boot — the validator does not check provider names against the
> registry to keep the config package decoupled from credstore.

Per-rule routing is inferred from the `secret_ref` scheme. When the
config has exactly one credstore for a given provider, rules don't need
to name their credstore explicitly; when two credstores share a
provider, the rule must pin `credstore: <name>` (this routing override
is forthcoming; the current build rejects multi-credstores-per-provider
at boot).

The legacy single-credstore form — a top-level `token:` block and no
`credstores:` list — is normalized into a synthesized `"default"`
credstore at load time. Configs that set both forms are rejected with a
clear lint.

## Settings

The optional `settings:` map on a credstore carries **non-secret,
provider-interpreted** configuration — things like a self-hosted server URL
that aren't a token and aren't part of the `secret_ref`. The keys are defined
by each provider; `postern config validate` asks the provider to vet them, so
an unknown key or a malformed value is a line-numbered error rather than a
silently ignored field. The 1password provider recognizes no keys (any setting
is rejected); the bitwarden provider's keys are listed below.

## Bitwarden Secrets Manager

The `bitwarden` provider brokers secrets from Bitwarden Secrets Manager (the
machine-oriented surface, authenticated by a machine access token — the analog
of a 1Password Service Account). It does not link the Bitwarden SDK; it shells
out to the **`bws` CLI**, which must be on the broker's `PATH` at runtime (or
pointed at by `settings.bws_path`).

- **Name:** `bitwarden` · **Scheme:** `bw`
- **`secret_ref` grammar:** `bw://<secret-uuid>` — the UUID of a Secrets
  Manager secret. There is no field selector: the secret's *value* is the
  credential. A non-UUID id, or a non-empty reserved vault segment, fails
  closed before any subprocess is spawned.
- **Token:** a Bitwarden machine access token supplied through the standard
  `token:` block. At resolve time it is passed to `bws` via the
  `BWS_ACCESS_TOKEN` environment variable in a minimal, non-inherited
  environment — never on argv.

### Settings keys

| Key | Required | Meaning |
|---|---|---|
| `server_url` | no | Self-hosted base URL (e.g. `https://vault.example.com`). Passed to `bws` as `--server-url`; the API and identity endpoints derive from it. Omit for the Bitwarden cloud. Must be an absolute `http`/`https` URL. |
| `bws_path` | no | Absolute path to the `bws` binary. Defaults to resolving `bws` on `PATH`. |

### Config example

```yaml
credstores:
  - name: bitwarden-sm
    provider: bitwarden            # the registered Name, not the "bw" scheme
    token:
      source: env
      env_var: BWS_ACCESS_TOKEN
    settings:
      server_url: https://vault.example.com   # omit for the Bitwarden cloud

proxy:
  listen: 127.0.0.1:14321
  cache_ttl: 5m

rules:
  - host: api.anthropic.com
    secret_ref: bw://7f9c2b3a-1d4e-4a6f-8b2c-0e1f2a3b4c5d
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
```

### Providing `bws`

postern publishes **no** image or release that bundles `bws`: the bws CLI is
GPL-3.0, postern is Apache-2.0, and we redistribute nothing GPL. You acquire
`bws` from Bitwarden upstream.

- **Containers** — layer the upstream `bws` image onto postern with a
  digest-pinned multi-stage build. The upstream image is multi-arch
  (linux/amd64 + linux/arm64) and ships a static binary at `/bin/bws`:

  ```dockerfile
  FROM ghcr.io/bitwarden/bws:2.1.0@sha256:3927158c53ac5a17d6cbe59fc3e1353e426f168bf246dbfe3668f6de5eaa107f AS bws
  FROM ghcr.io/mmartinez/postern:<version>
  COPY --from=bws /bin/bws /usr/local/bin/bws
  ```

  Pinning by digest is the integrity control: the registry guarantees the
  bytes behind that digest never change. Bump the digest deliberately when you
  move bws versions.

- **Hosts** — install `bws` yourself from Bitwarden's `sdk-sm` releases (or
  `cargo install bws`) and put it on `PATH`. The provider works as soon as
  `bws` is reachable; nothing in postern downloads it for you.

## Build tags for experimental providers

A provider that is not ready for general release should ship behind a
build tag so the default binary does not pull in the dependency:

```go
//go:build <tagname>

package myvendor

// ... implementation ...
```

Pair the tagged files with an untagged `doc.go` so `go build ./...`
still succeeds (an empty package directory is an error in Go).
CI compiles `go build -tags <tagname> ./...` on every PR so the
contract stays honest even when no tests run in the default suite.
Once a provider graduates, drop the build tag and add its side-effect
import to the default binary (the bitwarden provider followed this path).

## What you DON'T have to touch

- `internal/broker/`: the broker is provider-agnostic. It depends only
  on `broker.Resolver`.
- `internal/proxy/` and `internal/runtime/`: the proxy doesn't know
  credstores exist.
- `internal/cli/server.go`: the boot path iterates `cfg.CredStores` and
  consults the registry by Name; new providers come along for the
  ride.

## Testing checklist

- Unit-test `Name()` and `Scheme()` return the documented constants.
- Unit-test `NewResolver` against a stub of the vendor's API (use the
  interface-in-the-consumer pattern; don't mock the SDK type
  directly).
- Use the live SDK only behind an opt-in env var (e.g., `XX_E2E=1`)
  and an opt-in CI workflow trigger. See
  `internal/credstore/onepassword/live_test.go` for the pattern.
- The cache in `internal/credstore/onepassword/cache.go` is generic;
  consider reusing it rather than reimplementing TTL/LRU in your
  provider.
