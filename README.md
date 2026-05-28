# Postern

> A credential-brokering HTTPS proxy for AI agents, backed by 1Password.

Postern sits between AI agents and the APIs they call as a TLS-intercepting forward proxy. The agent never holds the real credential; Postern fetches it from 1Password (via Service Accounts) at request time and injects it into outbound traffic. The agent sees only placeholder values; Postern attaches the real secret on the way out.

**Status:** early development (pre-M1). Not yet usable.

## Host requirements

Postern is developed container-first. The host needs only:

- Docker (Engine 24+ or Desktop)
- git
- [devcontainer CLI](https://github.com/devcontainers/cli) (`npm i -g @devcontainers/cli`)

You do **not** need Go, golangci-lint, or any other Go tooling on the host. Everything runs inside the devcontainer.

## Getting started

```sh
git clone https://github.com/mmartinez/postern.git
cd postern
devcontainer up --workspace-folder .
make shell    # drop into the container
make test     # run the full Go test suite
make ci       # run lint + test + vuln + license check (what CI runs)
```

The first `devcontainer up` builds the image and primes named volumes for the Go module cache and build cache. Subsequent runs are fast.

## Project layout

```
.devcontainer/        # container definition (Dockerfile, devcontainer.json)
.github/workflows/    # CI
cmd/postern/          # CLI entry point
internal/             # all non-public packages
.mise.toml            # pinned toolchain (go, golangci-lint, lefthook, ...)
Makefile              # host-facing targets that wrap devcontainer exec
```

## Acknowledgments

Postern is inspired by [Infisical Agent Vault](https://github.com/Infisical/agent-vault), licensed under MIT. We are grateful to the Infisical team for open-sourcing their work on credential brokering for AI agents.

## Trademarks

1Password is a registered trademark of AgileBits Inc. Postern is not affiliated with, endorsed by, or sponsored by AgileBits or 1Password.

Infisical and Agent Vault are trademarks of Infisical Inc. Postern is an independent project and is not affiliated with, endorsed by, or sponsored by Infisical.

## License

Postern is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details. Portions derived from Infisical Agent Vault are subject to its MIT license; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (generated in CI).
