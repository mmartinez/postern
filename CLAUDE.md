## What postern is

A credential-brokering HTTPS forward proxy for AI agents. The agent calls outbound APIs without auth headers (or with placeholder values); postern matches the request host against YAML-declared broker rules, resolves the rule's credential reference from a pluggable credential provider (1Password Service Accounts, Bitwarden Secrets Manager), and injects it before forwarding. The agent never holds the real credential.

Apache-2.0 licensed.

## Development environment — container-first, non-negotiable

The host needs only Docker, git, and the devcontainer CLI. **No Go toolchain on the host.** Every Go, lint, test, format, and vuln tool lives inside the devcontainer, version-pinned by `.mise.toml`.

- Start the env once: `devcontainer up --workspace-folder .`
- Drop into a shell: `make shell`
- Anything Go-related goes through `make <target>`. From the host these wrap `devcontainer exec`; inside the container they are direct invocations. The Makefile auto-detects which side it's on.
- Bump tool versions in `.mise.toml` only. CI reads the same pins.

If a command fails on the host with "command not found", the fix is to run it via `make` (or inside `make shell`), not to install the tool globally.

## Commands

All Go work runs through `make`; on the host these wrap `devcontainer exec`.

- `make shell` — interactive shell inside the devcontainer.
- `make build` — build `dist/postern`.
- `make test` — full suite with `-race` and coverage.
- `make lint` — golangci-lint.
- `make ci` — lint + test + vuln + license check (what CI runs); run before pushing.
- `make snapshot` — local release build (binaries, archives, SBOMs, checksums; no publish/sign).
- `make licenses` — regenerate `THIRD_PARTY_NOTICES.md` after any dependency change.

## Project layout

- `cmd/postern/` — CLI entry point.
- `internal/broker/` — rule engine, the goproxy hook, credential injection, hot-reload.
- `internal/proxy/` — the MITM proxy (goproxy) and request handler.
- `internal/ca/` — local CA: generate, mint per-host leaf certs, OS trust-store integration.
- `internal/config/` — YAML schema, strict loader, line-numbered validation.
- `internal/credstore/` — provider registry plus the `onepassword/` and `bitwarden/` backends.
- `internal/token/` — service-account token storage (file and OS keyring).
- `internal/{runtime,logging,templates,version}/` — server assembly, slog setup, template rendering, build version.

## Git workflow

- **Commits run inside the devcontainer.** Lefthook hooks invoke gofumpt, golangci-lint, gitleaks, and a banned-strings check; the host has none of those.
- Commit messages follow **Conventional Commits**: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `build`, `ci`, `perf`, optionally with a scope (`feat(config): ...`). Enforced by the commit-msg hook.
- **Never bypass hooks.** No `--no-verify`. If a hook fails or hangs, fix the underlying issue — the hooks exist to catch bugs and leaks early.

## Working on a task

The project is sliced **vertically**: each task delivers a user-observable capability end-to-end through whatever layers it needs. No horizontal "build all models first, all handlers next" phases.

Per slice:

1. State scope before opening files. For non-trivial work, surface 2–3 viable approaches with tradeoffs and wait for review before coding.
2. **TDD.** Failing test first → confirm RED → minimum implementation to GREEN → refactor with tests still green. Skip TDD only for pure docs/config changes with no behavioral impact.
3. **Verify library/SDK shape against current docs before coding against it.** Training data is stale for the 1Password SDK, goproxy streaming semantics, 99designs/keyring backend enumeration, and several others.
4. **Coverage gate:** ≥ 80% on the core packages (broker, config, token, onepassword). Lower bar acceptable on glue code that is already exercised by integration tests.
5. One slice, one commit. Conventional commit message.

## Go conventions

We follow **Effective Go** and the **Google Go Style Guide**. The authoritative enforcer is `golangci-lint` (see the enabled linter set in `.golangci.yml`). The points below are the project-specific tightenings that don't fall out of lint automatically.

### Naming

- MixedCaps, never `snake_case` or `SHOUTING_CASE` for Go identifiers. (YAML values and env var names are strings, not identifiers, and follow their own conventions.)
- Initialisms stay uppercase as a block: `CacheTTL`, `URL`, `ID`.
- No `Get`-prefixed getters. The field `X` is read as `.X` or via a method `X()`, never `GetX()`.
- Constructors are `New<Type>` for the package's primary type, `New<Type><Variant>` for alternatives.
- File names are nouns (`schema.go`, `validator.go`, `cache.go`), not verbs.
- Receiver names are 1–2 characters and **consistent across all methods of a type**.
- Package names are short, lowercase, no underscores, no plurals.

### Comments

- Doc comments on **every exported identifier**, leading with the identifier's name. Enforced by `revive`.
- Inside function bodies, default to **no** comment. Comments explain *why* something non-obvious is the way it is — a hidden constraint, a workaround, a design choice a reader would legitimately question. If removing the comment wouldn't confuse a future reader, delete it.
- Package doc lives above the `package` keyword in one file per package. A paragraph at most.

### Errors

- Wrap with `%w`: `fmt.Errorf("read config: %w", err)`. Inspect with `errors.Is` and `errors.As`, never by string matching.
- Sentinel errors at the top of the file: `var ErrFoo = errors.New("...")`.
- Error messages are lowercase, no trailing punctuation, no leading capital. `"host is required"`, not `"Host is required."`.
- Return the `error` interface, not a concrete error type, unless callers genuinely need the concrete type.

### Control flow

- Guard-clause style: return early on errors instead of nesting the happy path inside `if err == nil { ... }`.
- `context.Context` is the first argument of every function that blocks, networks, or reads from a cancellable source. Name it `ctx`.

### Interfaces

- Define interfaces in the **consumer** package, not the producer's. Small and focused. Exception: packages whose only purpose is to wrap a third-party library (1Password SDK, OS keychain) define their own interfaces so consumers can use fakes in tests.
- Accept interfaces, return structs (or struct pointers).

### State

- **No global mutable state outside** `main`**.** Pass loggers, clocks, and configs explicitly. The one accepted exception is the `Version` string set by ldflags at build time.
- Logging is stdlib `log/slog` only, with an explicit logger passed in. Never log a credential value or a fingerprint of one.

### YAML & config

- Strict mode (`yaml.KnownFields(true)`). Unknown fields are an error.
- Validation surfaces line numbers via `yaml.Node` walking. Schema errors must tell the user which line is wrong, never a bare parser trace.

## Testing

- Stack: stdlib `testing` + `stretchr/testify/require` + `google/go-cmp/cmp` + `net/http/httptest` + hand-written fakes behind narrow interfaces. No mock-generator framework.
- `t.Parallel()` everywhere safe.
- Table-driven for anything with more than two cases. Subtests via `t.Run(tc.name, ...)`.
- **No** `time.Sleep` **in tests.** Use injectable clocks (interface or a clock library).
- **Never mock the database / keychain / SDK in tests whose job is to validate that the database / keychain / SDK works.** Use the real implementation, or a live test gated by an opt-in env var.
- Race detector on always. Pre-push and CI both run with `-race`.
- Integration tests live alongside the package they exercise (`*_integration_test.go`), build the binary with `go build`, and drive it via `exec.Cmd`. The install-script end-to-end test lives under `test/install/`.

## Releases

release-please + goreleaser, driven by Conventional Commits:

- Pushing `feat`/`fix` commits to `main` keeps a release-please "Release PR" open (version bump + `CHANGELOG.md`).
- Merging that PR publishes the GitHub release and tag; the same workflow run then builds the CGO matrix and uploads the binaries, checksums, SBOMs, and the keyless cosign bundle, and pushes the signed multi-arch ghcr image (`release.mode: keep-existing`).
- `feat` bumps the minor, `fix` the patch (pre-1.0). Repository release immutability is **off** — it rejected the asset-upload step; cosign signatures cover artifact integrity.

## Working with secrets

This is a credential-brokering tool — be paranoid about leakage.

- Never write a credential, token, or secret value to **any** log, stdout, stderr, file, or test fixture. Use the masking helper when you need to reference one in output (`first4…last4` form).
- A banned-strings gate blocks literal vendor brand names in Go and YAML files outside of the user-facing docs and the gate's own config. This protects against accidental trademark misuse.
- gitleaks runs pre-commit and across full history in CI.
- The runtime **fails closed**: any credential resolver error returns 502 to the agent and does **not** call the upstream. Tests must assert the upstream-side counter stayed at zero.

## Things never to do

- Commit anything to the untracked planning artifacts.
- Install Go tooling on the host.
- Bypass lefthook with `--no-verify`.
- Skip TDD on behavioral code "for speed."
- Use a regex when a single-`*` glob suffices for host patterns.
- Add a dependency without regenerating `THIRD_PARTY_NOTICES.md`(run `make licenses`).
- Add anything under `pkg/`. App code lives under `internal/`.

## When you finish a task

- `make ci` is clean inside the container.
- Coverage on changed packages is at or above the gate.
- A commit per slice has landed with a Conventional Commit message.
- CI is green on the resulting commit before moving to the next task.