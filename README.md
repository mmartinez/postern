# Postern

[![CI](https://github.com/mmartinez/postern/actions/workflows/ci.yml/badge.svg)](https://github.com/mmartinez/postern/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![1Password — supported](https://img.shields.io/badge/1Password-supported-0572EC?logo=1password&logoColor=white)](docs/providers.md)
[![Bitwarden — supported](https://img.shields.io/badge/Bitwarden-supported-175DDC?logo=bitwarden&logoColor=white)](docs/providers.md)

> **Your AI agents call authenticated APIs without ever holding the credentials.**

Postern is a credential-brokering HTTPS proxy. Agents send requests with no API
keys (or with harmless placeholders); postern matches the destination host
against your rules, fetches the real secret from your **1Password or Bitwarden**
vault at request time, and injects it on the way out. The agent only ever sees
placeholders.

**Works with [1Password](https://1password.com/) (Service Accounts) and
[Bitwarden](https://bitwarden.com/products/secrets-manager/) Secrets Manager** —
credential providers are [pluggable](docs/providers.md).

**Why it matters:** an agent that can read a credential is a credential an
attacker can exfiltrate through prompt injection or a compromised dependency.
Brokering moves the secret out of the agent's reach entirely — the blast radius
of a compromised agent no longer includes your API keys.

## See it

Your agent makes a normal request through the proxy, with **no `Authorization`
header**:

```sh
curl -x http://localhost:1701 \
  https://api.anthropic.com/v1/messages \
  -d '{ "model": "claude-sonnet-4-6", "messages": [ ... ] }'
#  ↑ no API key anywhere in the agent's environment or request
```

Postern matches `api.anthropic.com`, resolves `bw://…`/`op://…` from your vault,
injects the key, and forwards the now-authenticated request. The upstream sees a
valid call; the agent never touched the secret. On any resolver error postern
**fails closed** with a `502` and never contacts the upstream.

## How it works

The agent points `HTTPS_PROXY` at postern and trusts its local CA. For each
request, postern matches the destination host against YAML-declared rules,
resolves the matched rule's secret reference from a credential provider, injects
the credential, and forwards the request. The full request lifecycle and trust
boundary are in [docs/architecture.md](docs/architecture.md).

The matched rule's secret reference (`op://…` or `bw://…`) resolves from the
configured provider; adding a new provider is a single package. See
[docs/providers.md](docs/providers.md).

> **Status:** early development. The proxy works end-to-end, and the release
> pipeline (checksum-verified binaries, SBOMs, and a signed multi-arch container
> image) publishes from the first tagged release (`v0.1.0`) onward. **Linux
> amd64/arm64 only** — macOS and Windows are deferred until there is demand.

## Install

> Prebuilt binaries and the container image publish from `v0.1.0` onward. Until
> then, [build from source](#developing-postern).

### Binary

```sh
curl -fsSL https://raw.githubusercontent.com/mmartinez/postern/main/install.sh | sh
```

The script detects your architecture, downloads the release tarball and
`checksums.txt`, verifies the SHA-256, and installs to `/usr/local/bin/postern`.
Use `sudo` for that default location, set `POSTERN_INSTALL_DIR` to install
elsewhere, or `POSTERN_VERSION` to pin a release.

The SHA-256 check guards against a corrupted or truncated download, **not**
against a tampered release: `checksums.txt` comes from the same source as the
tarball, so an attacker who can rewrite the release rewrites both. For
supply-chain assurance, verify the keyless [cosign](https://docs.sigstore.dev/)
signature before trusting a download (or verify the signed container image by
digest):

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/mmartinez/postern/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

### Docker

The image is **`ghcr.io/mmartinez/postern`** (multi-arch linux/amd64 + arm64),
distroless and non-root (uid 65532). The vendor token is delivered as a mounted
secret, never baked into the image or its environment (the CI build asserts this
on every snapshot). See [Docker Compose](#docker-compose) for a runnable
example.

## Quick start

From an installed binary (or `./dist/postern` when building from source):

```sh
postern ca install        # generate a local CA and add it to your trust store
postern config init       # write a starter ~/.postern/config.yaml
postern token set --stdin # store your vault service-account / machine token

# edit ~/.postern/config.yaml to add rules for the APIs your agent calls, then:
postern server            # run the proxy

# in the agent's shell, wire HTTPS_PROXY + CA trust in one step:
eval "$(postern bootstrap)"
```

`postern config validate` checks a config with line-numbered errors, and
`postern rules list` shows the loaded rules (never the resolved credentials).
Every field is documented in [docs/configuration.md](docs/configuration.md).

A minimal config:

```yaml
credstores:
  - name: vault
    provider: 1password               # or: bitwarden
    token:
      source: env
      env_var: OP_SERVICE_ACCOUNT_TOKEN

proxy:
  listen: 127.0.0.1:1701
  cache_ttl: 5m

rules:
  - host: api.anthropic.com
    secret_ref: op://Agents/Anthropic/api_key   # or: bw://<secret-uuid>
    inject:
      type: header
      name: x-api-key
      template: "{{ CREDENTIAL }}"
```

## Deployment

### Docker Compose

`docker-compose.yml` in the repo root runs the proxy with the token as a Docker
secret and the CA mounted read-only. It expects two files alongside it:

- **`op_token`** — a `0600` file containing your vault token. Never commit it.
- **`config.yaml`** — point the token source at the mounted secret and bind to
  all interfaces:

  ```yaml
  token:
    source: file
    file: /run/secrets/op_token
  proxy:
    listen: 0.0.0.0:1701
    cache_ttl: 5m
  rules:
    - host: api.anthropic.com
      secret_ref: op://Agents/Anthropic/api_key
      inject:
        type: header
        name: x-api-key
        template: "{{ CREDENTIAL }}"
  ```

postern's CA is generated once, then read-only for its ~10-year life (the proxy
only reads it to sign per-host leaf certs in memory). Bootstrap it once, then
start the proxy:

```sh
mkdir -p postern-ca
export POSTERN_UID="$(id -u)" POSTERN_GID="$(id -g)"   # run as your uid so it can read the CA you generate
docker compose run --rm bootstrap                      # one-time: generate the CA into ./postern-ca
docker compose up -d                                   # run the proxy
```

Distribute `./postern-ca/.postern/ca.pem` to your agents, point them at the
proxy, and have them trust the CA:

```sh
export HTTPS_PROXY=http://localhost:1701
export SSL_CERT_FILE=/path/to/ca.pem                   # NODE_EXTRA_CA_CERTS for Node-based agents
```

Rotating the CA (at its ~10-year expiry, or on key compromise) is just
re-running `docker compose run --rm bootstrap` and redistributing `ca.pem`.

### systemd

On a non-container Linux host, deliver the token with systemd's credential store
so it never lands in the unit's environment or on disk unencrypted:

```ini
[Service]
ExecStart=/usr/local/bin/postern server --config /etc/postern/config.yaml
LoadCredential=op_token:/etc/postern/op_token
```

Set `token.source: file` and `token.file:
/run/credentials/postern.service/op_token` in `config.yaml`; systemd mounts the
token read-only into the unit's private credentials directory for the lifetime of
the process.

## Documentation

- [Architecture](docs/architecture.md) — request lifecycle, trust boundary, components.
- [Security model](docs/security.md) — fail-closed semantics, logging, threat model, key handling.
- [Configuration](docs/configuration.md) — the full YAML reference.
- [Providers](docs/providers.md) — the credential-vendor plugin contract (1Password, Bitwarden).

## Developing postern

Postern is developed **container-first**. The host needs only Docker, git, and
the [devcontainer CLI](https://github.com/devcontainers/cli) — no Go toolchain.

```sh
git clone https://github.com/mmartinez/postern.git
cd postern
devcontainer up --workspace-folder .   # build the container (once)
make shell                             # drop into it
make build                             # produces dist/postern
make ci                                # lint + test + vuln + license check (what CI runs)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow, conventions, and
how the git hooks work.

## Security

To report a vulnerability, follow [SECURITY.md](SECURITY.md) — please do not open
a public issue. The security model (what postern defends, what it does not, and
how it handles keys and tokens) is documented in [docs/security.md](docs/security.md).

## Trademarks

1Password is a registered trademark of AgileBits Inc. Bitwarden is a trademark of
Bitwarden, Inc. Postern is not affiliated with, endorsed by, or sponsored by
AgileBits, 1Password, or Bitwarden.

## License

Postern is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for
details. Bundled third-party dependencies and their licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (generated in CI).
