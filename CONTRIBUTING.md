# Contributing to Postern

Thanks for your interest in contributing. This guide covers the development
setup and the conventions the project enforces.

## Development environment

Postern is developed **container-first**. The host needs only:

- Docker (Engine 24+ or Desktop)
- git
- the [devcontainer CLI](https://github.com/devcontainers/cli)
  (`npm i -g @devcontainers/cli`)

Do not install Go or Go tooling on the host.
The toolchain is version-pinned inside the devcontainer.

```sh
devcontainer up --workspace-folder .   # build/start the container (once)
make shell                             # drop into a container shell
```

Every Go, lint, test, and format task runs through `make`.
From the host the targets wrap `devcontainer exec`; inside the container they run directly.
Keep tool versions in `.mise.toml` and the corresponding CI workflow pins in sync.
After changing the Go pin, run `bash .devcontainer/post-create.sh` inside `make shell` to reinstall tools for that Go version.

## Web components

The site at `web/site/` is a self-contained npm project, like every future
component under `web/`. Its commands run through the devcontainer too:

```sh
make site-install   # install dependencies from the lockfile
make site-dev       # Astro dev server on port 4321
make site-build     # static build into web/site/dist/
make site-ci        # clean install and build, the way CI does it
```

Node is pinned in `.mise.toml`, in lockstep with `NODE_VERSION` in the CI
workflow. Never put Go code under `web/`, and never run npm in the release
workflow.

## What CI runs

A `changes` job classifies every pull request. The Go jobs are skipped only
when every changed file is under `web/site/`; the `site` job runs when the site
changed. Anything else, including other paths under `web/`, runs the Go jobs
too. `ci-ok` aggregates the results and is the single status check that matters.

Keep site changes in site-only pull requests, so the Go jobs stay skipped. A
pull request that touches the site and root files together counts as a backend
change for release-please: give it a non-releasable type (`ci`, `docs`,
`chore`). `build` cuts a release, like `feat`, `fix`, and `perf`.

## Before you open a pull request

Run the full local pipeline and make sure it is green:

```sh
make ci    # publication + lint + test (race) + vulncheck + license check
```

- **Tests pass under the race detector** (`make test` runs with `-race`).
- **Lint is clean** (`golangci-lint`, configured in `.golangci.yml`).
- Aim for at least 80% coverage on broker, config, token, and onepassword.
  This is a project target, not an enforced CI threshold. Integration-tested
  glue code may have lower unit-test coverage.

## Commits

- Follow [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): subject`, e.g. `fix(broker): fail closed on resolver error`.
  Allowed types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `build`,
  `ci`, `perf`. A commit-msg hook enforces the format.
- Keep generated authorship and execution provenance out of commits and pull
  requests. Configure contribution tools to omit attribution trailers and
  generated-content signatures. Human co-author credit is welcome.
- Keep changes surgical: each changed line should trace to the change you are
  making. Don't reformat or refactor unrelated code in the same commit.

## Public content boundary

This repository is public.
The boundary covers tracked files, code comments, commit messages and metadata, branch names, pull request titles and bodies, tags, release notes, and published artifacts.

- Do not publish private ticket identifiers, tracker or workspace links,
  planning artifacts, local contributor instructions or settings, or execution
  provenance such as model names, internal roles, and session or run identifiers.
- Keep private tracking one-way. A private record may link to a public commit or
  pull request. Public content must not link back to or name the private record.
- Use neutral, descriptive branch names such as `fix/request-validation`, not
  ticket identifiers or execution-role prefixes.
- Describe the change, its user-visible behavior, and verification results.
  Product documentation for supported agents and skills is welcome, as are
  ordinary test-harness descriptions. These are not execution provenance.
- Keep local instructions and private planning files outside the tracked tree.
  Use `.git/info/exclude` for local-only exclusions. Never add a real secret or
  private identifier as a test fixture or as an example of rejected content.

Before committing or publishing, run the publication gate in the devcontainer:

```sh
make publication
```

This runs the focused gate tests, then scans the tracked working tree and current branch name.
Hooks also check staged content from the index, commit messages, and outgoing commits before a push.
The gate reports only the location and category of a finding, never the rejected text.
If the filename itself contains rejected text, the diagnostic omits it.

For a specific input, enter `make shell` and run:

```sh
node scripts/check-publication.mjs --staged
node scripts/check-publication.mjs --message-file .git/COMMIT_EDITMSG
node scripts/check-publication.mjs --range origin/main..HEAD
```

The commit-range check covers newly published commit metadata and file contents, not historical commits outside that range.
The pre-push hook reads Git's outgoing ref updates; new branches require an up-to-date remote-tracking `main` ref.
CI uses `--event PATH` to check event titles, bodies, branch names, and the event's commit range.

Release preflight uses `--release-inputs` to check the committed tree and release-note inputs since the latest released tag.
It checks effective commit messages, merged pull request titles and bodies, and supported commit-message overrides.
It reads GitHub through `gh` and requires `GITHUB_REPOSITORY` and `GH_TOKEN` with read access to contents and pull requests.
It does not change remote state or scan historical pull request branch names.
Release draft text uses the header and footer in `release-please-config.json`.

Review release notes and other publication text manually before sending them.
Pattern checks cannot identify every private domain or execution reference and do not replace that review.

Repository-owner authorization is required for merges, tags, releases, publishing workflows, and history changes.
Do not force-push or rewrite published history without that authorization.
Do not use destructive resets or discard another contributor's work to make checks pass.

## Git hooks

Commits are gated by [lefthook](https://github.com/evilmartians/lefthook):
formatting, lint, secret scanning, publication checks, and a brand-name check.
The hooks run inside the devcontainer, so **run `git commit` from a container
shell** (`make shell`).
**Never bypass the hooks** (`--no-verify`); they exist to catch bugs and
credential leaks before they land. If a hook fails, fix the cause.

## Engineering standards

Keep each change small and deliver its user-visible behavior across all
affected layers. Discuss non-trivial designs and tradeoffs before coding.
Verify library and SDK APIs against current documentation before using them.
Application code belongs under `internal/`, not `pkg/`.

Follow Effective Go and the Google Go Style Guide. The linter enforces the
configured rules; these conventions also apply:

- Use MixedCaps and uppercase initialisms. Avoid `Get`-prefixed getters.
  Name constructors `New<Type>` or `New<Type><Variant>`, files with nouns,
  and packages with short, lowercase singular names. Keep receiver names
  short and consistent across a type's methods.
- Document exported identifiers with comments starting with their names.
  Keep one short package comment per package. Other comments explain
  non-obvious constraints or decisions, not what the code already says.
- Wrap errors with `%w`; inspect them with `errors.Is` or `errors.As`.
  Use lowercase error messages without trailing punctuation. Declare
  sentinels at file scope and return the `error` interface unless callers
  need a concrete type.
- Return early on errors. Put `context.Context` first, named `ctx`, for
  blocking, network, or cancellable operations.
- Define small interfaces in the consuming package. Third-party adapters
  may define their own interfaces for tests. Accept interfaces and return
  concrete types.
- Pass loggers, clocks, and configuration explicitly. Do not add global
  mutable state outside `main`; build-time version metadata and the provider
  registry are existing exceptions. Use `log/slog` for logging.
- Reject unknown YAML fields and report validation errors with source line
  numbers. Use the existing single-`*` glob rules for host matching rather
  than introducing regular expressions.

## Tests

- For behavioral changes, write a failing test, confirm it fails, then add
  the minimum implementation and refactor with tests passing. Pure prose or
  non-behavioral configuration changes do not require a new test.
- Use standard library `testing`, `stretchr/testify/require`,
  `google/go-cmp/cmp`, `net/http/httptest`, and hand-written fakes behind
  narrow interfaces. Do not add a mock generator.
- Use table-driven subtests for more than two cases and `t.Parallel()` when
  safe. Use injectable clocks instead of `time.Sleep`.
- Do not mock the credential vendor, keychain, or external CLI in a test whose job is to prove that integration works.
  Use the real implementation, or an opt-in live test gated behind an environment variable.
- Keep integration tests beside their packages in `*_integration_test.go`.
  CLI integration tests build and drive the binary with `exec.Cmd`; installer
  end-to-end tests live under `test/install/`.
- Assert fail-closed behavior at the upstream boundary. When credential
  resolution fails without a usable cached value, the request must return
  502 and the upstream request count must remain zero. Cached values may be
  served only within the configured staleness limit.

## Working with secrets

Postern is a credential broker. Never print or copy a real credential, token,
or secret into logs, stdout, stderr, reports, files, or test fixtures while
developing or debugging. Do not dump runtime configuration, credential stores,
or environments to investigate a failure. Use synthetic fixtures.

Production credential storage and injection must use the existing controlled
paths. Keep secret values and fingerprints out of logs. Where a user-facing
command must identify a value, use the existing masking helper, never raw
output. A secret scanner runs on every commit and across history in CI.

## Releases

Release automation uses Conventional Commits. Backend `feat`, `fix`, `perf`,
and `build` changes update the release pull request. Merging it creates the
release and tag, then publishes signed artifacts. Only the repository owner
may authorize these operations. Backend release tags use `vX.Y.Z`.

For local artifacts without publishing or signing, use `make snapshot`.
If asset publication fails, the owner can dispatch `release.yml` with the
existing tag to repair that release. Re-running the original failed workflow
does not repeat release creation.

## License

By contributing, you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE). Adding a dependency requires
regenerating the third-party notices (`make licenses`).
