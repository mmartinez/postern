# Contributing to Postern

Thanks for your interest in contributing. This guide covers the development
setup and the conventions the project enforces.

## Development environment

Postern is developed **container-first**. The host needs only:

- Docker (Engine 24+ or Desktop)
- git
- the [devcontainer CLI](https://github.com/devcontainers/cli)
  (`npm i -g @devcontainers/cli`)

You do **not** install Go or any Go tooling on the host — the toolchain is
version-pinned inside the devcontainer.

```sh
devcontainer up --workspace-folder .   # build/start the container (once)
make shell                             # drop into a container shell
```

Every Go, lint, test, and format task runs through `make`. From the host the
targets wrap `devcontainer exec`; inside the container they run directly (the
Makefile detects which side it is on). Bump tool versions only in `.mise.toml`.

## Before you open a pull request

Run the full local pipeline and make sure it is green:

```sh
make ci    # lint + test (race) + vulncheck + license check
```

- **Tests pass under the race detector** (`make test` runs with `-race`).
- **Lint is clean** (`golangci-lint`, configured in `.golangci.yml`).
- **Coverage** stays at or above the bar on the core packages.

## Commits

- Follow [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): subject`, e.g. `fix(broker): fail closed on resolver error`.
  Allowed types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `build`,
  `ci`, `perf`. A commit-msg hook enforces the format.
- Keep changes surgical: each changed line should trace to the change you are
  making. Don't reformat or refactor unrelated code in the same commit.

## Git hooks

Commits are gated by [lefthook](https://github.com/evilmartians/lefthook):
formatting, lint, secret scanning, and a brand-name check. The hooks run inside
the devcontainer, so **run `git commit` from a container shell** (`make shell`).
**Never bypass the hooks** (`--no-verify`); they exist to catch bugs and
credential leaks before they land. If a hook fails, fix the cause.

## Tests

- Write a failing test first, then the minimum code to pass it
  (test-driven development).
- Standard library `testing` with `stretchr/testify`; table-driven tests for
  anything with more than two cases.
- Do not mock the credential vendor, keychain, or external CLI in a test whose
  job is to prove that integration works — use the real implementation, or an
  opt-in live test gated behind an environment variable.

## Working with secrets

Postern is a credential broker. **Never** write a credential, token, or secret
value to a log, stdout, stderr, a file, or a test fixture. Reference one in
output only through the masking helper (`first4…last4`). A secret scanner runs on
every commit and across history in CI.

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE). Adding a dependency requires
regenerating the third-party notices (`make licenses`).
