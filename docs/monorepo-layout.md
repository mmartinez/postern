# Monorepo layout

> **Status: accepted design, not yet implemented.** Nothing has moved yet.
> Stages 2–4 of the [execution checklist](#execution-checklist) carry it out;
> update this line as they land.

This repository is becoming a monorepo for three components:

| Component | What it is | Path | Exists |
|---|---|---|---|
| **postern** | The Go backend: the `postern` binary, its container image and its installer. Module `github.com/mmartinez/postern`. | repository root | yes |
| **site** | The marketing landing page served at `https://postern.dev`: an Astro + Tailwind static site, today in the private `mmartinez/postern-web` repository. | `web/site/` | yes; imported in Stage 3 |
| **app** | The postern app web frontend. | `web/app/` (reserved) | not yet |

This document records the target layout, why it beats the alternatives, what
happens to every piece of repository tooling, how `postern-web` comes in, how
the components are versioned, and the order in which it all lands.

## Decisions at a glance

| Question | Decision |
|---|---|
| Where does the Go backend live? | Where it lives now, at the repository root. **No Go file moves.** |
| Where do the web frontends live? | Under `web/`, one self-contained npm project per component: the landing page at `web/site/`, the future app at `web/app/`. `web/` itself is only a namespace; no component owns it. |
| Go module path | Unchanged: `github.com/mmartinez/postern`. `go.mod` gains one line, `ignore ./web`. |
| Importing `postern-web` | A snapshot copy of `postern-web@e4ca727` into `web/site/` in one squash-merged PR. The old repository is archived, not rewritten. |
| Versioning | One released component today: the backend, with its `vX.Y.Z` tags and pipeline unchanged. release-please ignores commits that touch only `web/site/`. The site is unversioned and built on every change. The app's release model is decided when the app is designed ([The reserved app home](#the-reserved-app-home)). |
| CI | Go jobs are skipped only when a pull request touches nothing outside `web/site/`. A `site` job runs when the site changes, and a `ci-ok` job aggregates the result. Skips happen at job level, and a classifier failure runs everything. |

## Target layout

```text
postern/
├── go.mod, go.sum          Go module root, github.com/mmartinez/postern (+ `ignore ./web`)
├── cmd/postern/            CLI entry point
├── internal/               backend packages
├── test/{e2e,install}/     black-box suites
├── web/                    web frontends: Node toolchain territory, no Go
│   ├── README.md           index of the web components              (new, Stage 3)
│   ├── site/               marketing landing page, postern.dev       (new, Stage 3, from postern-web)
│   │   ├── package.json, package-lock.json, .npmrc, .gitignore
│   │   ├── astro.config.mjs, tailwind.config.mjs, tsconfig.json
│   │   ├── src/            layouts/, pages/, env.d.ts
│   │   └── public/         favicon.svg
│   └── app/                reserved: the postern app web frontend    (created by the app's first PR)
├── docs/                   project documentation
├── scripts/                repository tooling
├── install.sh              one-line installer (its raw URL is published)
├── Dockerfile, docker-compose.yml, .goreleaser.yaml
├── release-please-config.json, .release-please-manifest.json, CHANGELOG.md
├── Makefile, .mise.toml, lefthook.yml, .devcontainer/   shared by all components
└── .github/                workflows/{ci,release}.yml, dependabot.yml
```

Everything not marked new stays exactly where it is. Rules for placing new files:

- **Go code** goes under `cmd/` or `internal/`. Never under `web/`, never in `pkg/`.
- **Web code** goes in the component it belongs to, `web/site/` or `web/app/`.
  Each component is a self-contained npm project with its own `package.json`,
  lockfile, `.gitignore` and build. There is no root `package.json`, and nothing
  outside `web/` belongs to an npm project.
- **Repository-wide tooling** (hooks, CI, toolchain pins, the devcontainer)
  stays at the root: one copy, shared by every component.
- **A new web component** is a new directory under `web/` with its own
  Dependabot entry, CI job and classifier branch. The `web/`-wide settings
  (`go.mod`'s `ignore`, `.dockerignore`) already cover it.

`web/app/` is reserved by name, here and in `web/README.md`. It is not created
as an empty placeholder: an npm project without a `package.json` only breaks
the tools that look for one, Dependabot among them. The app's first pull
request creates it.

## Why this layout

### Go keeps a single module at the root

The Go project's guidance for a repository with one Go deliverable is a single
module at the root. The modules FAQ is direct: "managing a single-module
repository is almost always easier and simpler" than managing several
([go.dev/wiki/Modules](https://go.dev/wiki/Modules)). The official layout guide
puts a server's `go.mod`, `cmd/` and `internal/` at the repository root, and
keeps commands in `cmd/` because "the project is likely to have many other
directories with non-Go files"
([go.dev/doc/modules/layout](https://go.dev/doc/modules/layout)). Postern
already has that layout; the web frontends are more non-Go directories beside
it.

Moving the module into a subdirectory is not free in Go. A module outside the
repository root has that subdirectory in its module path, and its version tags
carry it as a prefix: `backend/v0.11.0`, not `v0.11.0`
([go.dev/ref/mod](https://go.dev/ref/mod#vcs-version)). All of postern's
release machinery assumes plain `vX.Y.Z` tags (see
[Alternatives considered](#alternatives-considered)).

Go 1.25 added the tool for keeping non-Go trees out of a module's builds: the
`go.mod` `ignore` directive makes the go command skip a directory when matching
package patterns such as `./...` and `all`
([go.dev/doc/go1.25](https://go.dev/doc/go1.25)). One line isolates `web/` from
every Go tool postern runs ([verified](#go-module)).

### Go projects with web frontends already use this shape

Prometheus (`web/ui/`), Vault (`ui/`), Traefik (`webui/`), Woodpecker (`web/`),
PocketBase (`ui/`) and Argo CD (`ui/`) all keep their Go module at the root,
with the JavaScript code in a sibling directory. Two are close to postern's
three-component plan:

- **Nomad** and **Vault** keep the Go backend at the root and the product's
  web UI in `ui/`, and both also kept their public documentation website in a
  sibling `website/` directory.
- **Prometheus** keeps more than one web app (`mantine-ui/`, `react-app/`) as
  siblings under one container, `web/ui/`, with the JavaScript workspace rooted
  in that container rather than at the repository root.

The counter-example is Mattermost, which split into `server/` and `webapp/`
and re-pathed its module to `github.com/mattermost/mattermost/server/v8`. That
is alternative C below, with C's costs.

### `web/` is a namespace, and each component gets a named directory

The landing page and the app are different kinds of software. The site is
public, static marketing content deployed to postern.dev; the app is product
code that ships with the backend or talks to it. Each gets a directory named
for its role, so neither name blocks the other:

- `site` is the public website: Astro's own term for it (`site:` in
  `astro.config.mjs`), and `postern-web`'s README calls it the "Marketing site
  for Postern". The name stays accurate if the landing page grows docs or a
  blog.
- `app` is the product's web frontend.

They share a container because the container is a real boundary: everything
under `web/` is built with Node, and nothing under it is Go. One prefix covers
every setting that holds for all web code (`go.mod`'s `ignore`,
`.dockerignore`), so starting `web/app/` touches none of them. If the site and
the app later share code, such as brand tokens or components, `web/` is where a
workspace root goes, as in Prometheus, without moving either package.

Why not `apps/site` and `apps/app`: in JavaScript monorepos `apps/` holds every
deployable, but here the main deployable, the Go backend, stays at the root. An
`apps/` directory that does not contain the app would mislead. Moving the
backend into `apps/postern` as well is alternative D.

### `postern-web` is the reference, and its conventions survive unchanged

`postern-web` is a stock, self-contained Astro project: manifest, lockfile and
`.gitignore` at its root, `src/` and `public/` next to them, and `npm run build`
writing `dist/`. That shape becomes the contract for every web component.
Imported as one unit at `web/site/`, none of its source files change and none
of its relative paths move:
`npm --prefix web/site ci && npm --prefix web/site run build` does what
`npm ci && npm run build` did in the old repository. It has no workspace
tooling (no npm `workspaces`, no Turborepo or Nx), and with one npm project
there is nothing for a workspace to coordinate yet.

## Alternatives considered

These are the options for where the Go backend lives. The web layout above
holds for A, B and C; D renames it.

| | A. Backend at root, `web/{site,app}` (chosen) | B. `backend/` + web, module path kept | C. `backend/` + web, module re-pathed | D. `apps/{postern,site,app}` |
|---|---|---|---|---|
| Go files moved | none | all | all | all |
| Import paths rewritten | none | none | every Go file, and the ldflags `-X` paths | as B or C |
| `go install …/cmd/postern@vX` and pkg.go.dev | keep working | broken for every release after the move | new path; old path frozen at v0.10.x | as B or C |
| Tags, cosign identity, `install.sh` | unchanged | unchanged | tags become `backend/vX.Y.Z`; open-source goreleaser, `install.sh`, the README's cosign check and `release.yml`'s tag checks all change | as B or C |
| Path-sensitive tooling to rework | one `go.mod` line, one script | goreleaser, every Go CI job, devcontainer, Dependabot, lefthook, scripts, tests | B's list plus the release chain | as B or C |
| Open branches (PR #51 touches 13 files, 11 under `cmd/` and `internal/`) | unaffected | rebase across a mass rename | rebase plus import rewrite | as B or C |
| Symmetry between components | no: the backend owns the root | yes | yes | yes |

**B** keeps `module github.com/mmartinez/postern` in a `go.mod` that no longer
sits at that path. Everything still builds inside the repository, but the
module proxy resolves `github.com/mmartinez/postern@vX` from the repository
root, which no longer holds the module, so `go install` of the CLI and the
pkg.go.dev page break for every release after the move. The proxy serves every
tag through v0.10.2 today, so this is a live consumption path. Every tool that
assumes `go.mod` at the root must also learn the new directory: goreleaser
(`builds[].dir` and the `go mod tidy` hook), each Go CI job's working directory
and cache key, the devcontainer's `post-create.sh`, Dependabot's `gomod` entry,
lefthook's Go hooks, the banned-strings exemptions, the licenses script, and
`test/install/install_test.go:32`, which finds the root `install.sh` by a path
relative to itself.

**C** re-paths the module to `github.com/mmartinez/postern/backend`, which
makes it correct under Go's rules. That rewrites every import and the ldflags
`-X` paths (`.goreleaser.yaml:56-58` and `:94-96`), and Go then expects
`backend/vX.Y.Z` tags. Open-source goreleaser parses the current tag as semver
and fails on a prefixed one; tag-prefix support (`monorepo.tag_prefix`) is a
GoReleaser Pro feature. The installer (`install.sh:27` resolves
`releases/latest`, `install.sh:54` strips a leading `v`), the README's cosign
identity (`README.md:106`, `@refs/tags/v`) and `release.yml`'s repair checks
(`release.yml:93` and `:115-116`) all assume `v`-prefixed tags. That is the
release path PRs #100–#104 just finished hardening, rewritten for no
functional gain.

**D** is B or C under JavaScript-monorepo names, plus a workspace convention
with nothing to coordinate yet.

**The cost of A** is asymmetry: the backend owns the root, so root-level Go
tooling has to stay out of `web/`. In practice that is one `go.mod` line
(verified below) and one script change. B, C and D pay for symmetry with the
release pipeline.

## Go module

The module path stays `github.com/mmartinez/postern`. No file moves, no import
changes, no ldflags changes. Tags stay `vX.Y.Z`, which keeps four things the
same string: the Go module version, the release-please tag, the ref in the
cosign signing identity, and the version `install.sh` downloads.

`go.mod` gains one directive:

```go
ignore ./web
```

The leading `./` anchors the path at the module root. Without it, a directory
named `web` at any depth would be ignored.

This was verified with go1.27.2 (linux/arm64, `CGO_ENABLED=0`) on a scratch
copy of this tree with the site in place and a planted Go file under its
`node_modules/` that imports a module which does not exist:

- **Without the directive**, the planted file became a package of this module
  (`github.com/mmartinez/postern/web/…/node_modules/…`) and broke
  `go build ./...`. `go mod tidy`, which goreleaser runs before every release
  (`.goreleaser.yaml:17`), tried to resolve the planted import from the
  network: a website dependency could add modules to the backend's `go.mod`.
- **With the directive**, `go list ./...` returns the same 17 packages as
  today. `go build` and `go vet` (with and without `-tags bitwarden`),
  `go mod tidy` (a no-op), `golangci-lint run` 2.14.0 (0 issues),
  `govulncheck`, `go-licenses csv` (byte-identical output, so
  `THIRD_PARTY_NOTICES.md` cannot drift) and `gofumpt -extra -l .` 0.12.0 all
  skip `web/`. gofumpt walks the file tree itself and honors the directive as
  well.
- The directive is inert while `web/` does not exist, and `go mod tidy` keeps
  it.

Today's lockfile ships no Go sources (0 `.go` files across its 381 installed
packages), so the directive is a guard, not a fix.

One consequence is accepted: `ignore` does not remove `web/` from the module
zip, so `go install …@vX` downloads the site's sources (a few hundred
kilobytes) without compiling them.

**release-please:** the `go` strategy edits only `CHANGELOG.md`, since no
`version-file` is configured. The only change is the `exclude-paths` entry in
[Releases and versioning](#releases-and-versioning).

**goreleaser:** unchanged. `main: ./cmd/postern`, the ldflags, the archive
file list and `dockerfile: Dockerfile` all resolve as before, and the docker
pipe builds from a temporary context holding only the binary, so the image
never sees `web/`.

## Tooling plan

| File | Where it lives | Change | Stage |
|---|---|---|---|
| `go.mod`, `go.sum` | root (module root) | Add `ignore ./web`. Module path unchanged. | 2 |
| `release-please-config.json` | root | The `"."` package gains `"exclude-paths": ["web/site"]`. `release-type: go` and the top-level `include-component-in-tag: false` are unchanged. | 2 |
| `.release-please-manifest.json` | root | Unchanged. It tracks the backend version only. | — |
| `.goreleaser.yaml` | root | Unchanged ([Go module](#go-module)). | — |
| `Makefile` | root, the single entry point | Go targets unchanged (`fmt` too: gofumpt honors `ignore`). Add `site-install`, `site-dev`, `site-build` and `site-ci`, running `npm --prefix web/site …` through the same `$(RUN)` devcontainer wrapper. `ci` stays the Go gate. The app gets `app-*` targets when it exists. | 3 |
| `.github/workflows/ci.yml` | root | Stage 2: the `changes` classifier, the Go-job gates and `ci-ok`. Stage 3: the `site` job and `NODE_VERSION`. See [CI](#ci). | 2, 3 |
| `.github/workflows/release.yml` | root | Unchanged, and deliberately not path-filtered: release-please's `exclude-paths` is the one place that decides what counts as a backend change. It never gains a Node or npm step. | — |
| `.github/dependabot.yml` | root | Add an `npm` entry for `/web/site`: weekly, commit prefix `build`, labels `dependencies` and `web`. Existing entries unchanged. | 3 |
| `.mise.toml` | root, still the single source of truth | Add `node = "24.21.0"` (the current LTS, pinned exactly like Go), in lockstep with `NODE_VERSION` in `ci.yml`. Shared by every web component. | 3 |
| `lefthook.yml` | root | Unchanged. The pre-commit Go hooks are globbed to `*.go`, `secret-scan` already covers web files, `banned-strings` takes its exemption from the script, and the pre-push `./...` commands honor `ignore`. | — |
| `.devcontainer/` | root, one container for the repository | `devcontainer.json`: forward 4321 (the site's dev server) next to 1701, and add the Astro VS Code extension. `Dockerfile` and `post-create.sh` unchanged: mise installs Node from `.mise.toml`, and site dependencies install on demand through `make site-install`. | 3 |
| `Dockerfile` | root | Unchanged: the backend's production image. | — |
| `docker-compose.yml` | root | Unchanged: the backend's deployment example, which the README places "in the repo root". | — |
| `.golangci.yml` | root | Unchanged: golangci-lint 2.14 honors `ignore` (0 issues with a planted Go file under the site's `node_modules/`). | — |
| `.gitleaks.toml` | root | Unchanged. Web code is scanned like everything else: do not add a `web/` path allowlist. Lockfiles and `node_modules/` are already in gitleaks' default allowlist, which this config extends. | — |
| `.editorconfig` | root | Unchanged: the `[*]` defaults (UTF-8, LF, 2-space indent, final newline) already suit the site's files. | — |
| `.dockerignore` | root | Add `web/`, which keeps npm trees out of any build whose context is the repository root, such as CI's `devcontainer-build`. | 2 |
| `.gitignore` | root, plus one per web component | Root unchanged; `web/site/.gitignore` imported verbatim ([Folding in postern-web](#folding-in-postern-web)). | 3 |
| `scripts/check-banned-strings.sh` | root | Whole-tree mode scans the `git ls-files` output through the existing `is_exempt`/`is_scannable` filter, replacing its separate `grep -R` exclusion list; add `web/site/*` to `is_exempt`. | 2 |
| `scripts/gen-third-party-notices.sh`, `THIRD_PARTY_NOTICES.md` | root | Unchanged: these are the binary's notices, and `go-licenses csv ./...` output is byte-identical with the site present. | — |
| `install.sh` | root | Unchanged: its raw URL is published, and `test/install` finds it at `../../install.sh`. | — |
| `cmd/`, `internal/`, `test/`, `docs/` | root | Not moved. Documentation content is updated in Stage 4. | 4 |

Why the banned-strings change works the way it does: GNU grep's
`--exclude-dir` matches directory base names, so excluding `site` would silently
exempt any directory named `site` anywhere, a future Go package included. For a
security gate that is a quiet way to fail open. Filtering tracked paths through
`is_exempt` keeps every exemption exact and root-relative, leaves one exemption
list instead of two, and never reads an untracked `node_modules/` (11 YAML files
today). On the current tree both modes select the same 181 files.

## CI

### Classifying a change

A new `changes` job decides what a run has to cover:

```yaml
changes:
  runs-on: ubuntu-latest
  outputs:
    go: ${{ steps.classify.outputs.go }}
    site: ${{ steps.classify.outputs.site }}
  steps:
    - uses: actions/checkout@v7
      with:
        fetch-depth: 2
        persist-credentials: false
    - id: classify
      env:
        EVENT: ${{ github.event_name }}
      run: |
        set -euo pipefail
        go=true site=true
        if [ "$EVENT" = "pull_request" ]; then
          changed=$(git diff --name-only HEAD^1 HEAD)
          if [ -n "$changed" ]; then
            go=false site=false
            while IFS= read -r f; do
              case "$f" in
                web/site/*) site=true ;;
                .github/workflows/ci.yml | .mise.toml) go=true site=true ;;
                *) go=true ;;
              esac
            done <<< "$changed"
          fi
        fi
        echo "go=$go" >> "$GITHUB_OUTPUT"
        echo "site=$site" >> "$GITHUB_OUTPUT"
```

- On a `pull_request`, the checkout is GitHub's merge commit, so
  `git diff HEAD^1 HEAD` is exactly what merging would change.
- Go jobs are skipped only when **every** changed file is under `web/site/`.
  Everything else, including other paths under `web/`, runs them.
- A `push` to `main` or a `workflow_dispatch` runs everything, so `main` stays
  fully verified even after a site-only merge.
- No third-party paths-filter action: the logic decides whether the security
  gates run, and it is short enough to read in the workflow.

### Gating the jobs

Every existing Go job (`lint`, `typecheck`, `test`, `test-macos`, `vuln`,
`licenses`, `e2e`, `devcontainer-build`, `snapshot`) gains:

```yaml
needs: changes
if: ${{ !cancelled() && needs.changes.outputs.go != 'false' }}
```

- Skipping only on an explicit `'false'` means a failed or missing classifier
  runs everything. `!cancelled()` replaces the implicit `success()` check, so a
  failed `changes` job does not skip its dependents.
- `gitleaks` takes no `needs` and runs on every event: secrets do not respect
  path boundaries.
- The dispatch-only jobs (`token-keyring-e2e`, `op-live`) keep their current
  conditions.
- Skips are job-level `if` conditions, not workflow-level `paths:` filters.
  GitHub reports a job skipped by a condition as successful, while a workflow
  skipped by a path filter leaves its required checks pending and blocks the
  merge ([GitHub docs](https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution)).
  The `main` ruleset requires no status checks today; this keeps the design
  correct once it does.

### The `site` job (Stage 3)

```yaml
site:
  needs: changes
  if: ${{ !cancelled() && needs.changes.outputs.site != 'false' }}
  runs-on: ubuntu-latest
  permissions:
    contents: read
  defaults:
    run:
      working-directory: web/site
  steps:
    - uses: actions/checkout@v7
      with:
        persist-credentials: false
    - uses: actions/setup-node@v7
      with:
        node-version: ${{ env.NODE_VERSION }}
        cache: npm
        cache-dependency-path: web/site/package-lock.json
    - run: npm ci
    - run: npm audit signatures
    - run: npm run build
```

- `web/site/.npmrc` sets `ignore-scripts=true`, so no dependency install script
  runs, in CI or in the devcontainer. `npm run build` still works, because npm
  exempts scripts that are invoked explicitly. Verified: the site installs and
  builds this way on Node 22 and 24.21.0. Its three packages that declare
  install scripts (esbuild, sharp, fsevents) are not needed for a static build.
  If a future dependency really does need its script, run `npm rebuild <pkg>`
  for that one package rather than turning scripts back on.
- `persist-credentials: false` keeps the job token out of `.git/config`, where
  npm code running in the job could read it.
- `npm audit signatures` checks the registry signature of every installed
  package (381 verified today). `npm audit` for advisories is not a gate yet;
  see the maintainer decisions under
  [Folding in postern-web](#folding-in-postern-web).

### Aggregating: `ci-ok`

```yaml
ci-ok:
  if: ${{ always() }}
  needs: [changes, lint, typecheck, test, test-macos, vuln, licenses, e2e, gitleaks, devcontainer-build, snapshot, site]
  runs-on: ubuntu-latest
  steps:
    - env:
        RESULTS: ${{ toJSON(needs.*.result) }}
      run: |
        echo "$RESULTS"
        if echo "$RESULTS" | grep -Eq '"(failure|cancelled)"'; then exit 1; fi
```

A skipped job passes; a failed or cancelled one fails the gate. (Stage 2 lands
`ci-ok` without `site`, and Stage 3 adds it.) Once Stage 2 is in, `ci-ok` can
become the single required status check on `main`, which is a ruleset change
for the maintainer.

### Constraints on any future web workflow

- **No Node, npm or website step ever runs in `release.yml`.** Its jobs hold
  `contents: write`, `packages: write` and `id-token: write`, and the README
  tells users to verify signatures against the identity
  `release.yml@refs/tags/v…` (`README.md:106`). Website dependencies executing
  there could sign artifacts as postern.
- **A deploy workflow** (none exists today) lives in its own file, triggers on
  changes under its component's path on `main`, and holds only the permissions
  its host needs. Because the cosign identity pins both the workflow file and a
  `v` tag ref, a separate deploy workflow cannot produce a signature that users
  would accept for a postern release.

## Folding in postern-web

**Source.** `mmartinez/postern-web` at `e4ca727` (`main`, the merge of its PR
#1). The repository's default branch, `feat/marketing-site` (`ad75e62`), has the
same tree (`a2a5134`), so either gives byte-identical files. Its open PR #2 adds
a `CLAUDE.md` carrying the no-AI-attribution rule that this repository's
`CLAUDE.md` already has; the import supersedes it.

**Method: a snapshot copy.** The first commit is the copy and nothing else:

```sh
mkdir -p web/site
git -C ../postern-web archive e4ca727 | tar -x -C web/site
```

Its message records the source repository and the commit and tree hashes. A
second commit in the same PR makes the only edits: `web/site/package.json`
gets `"name": "postern-site"`, so it cannot be confused with the app, and
`"private": true`, so it can never be published to the npm registry; and
`web/site/.npmrc` is added.

History is not preserved, for four reasons:

- `main`'s ruleset requires linear history and allows only squash merges. A
  `git subtree add` or `read-tree` merge cannot land through a pull request,
  only by an admin bypassing the ruleset, which is the wrong way to land the
  biggest structural change the repository has had.
- There is nothing to keep: three commits, which are an init, a single commit
  holding the whole site, and a merge.
- A merge would graft an unrelated root commit and foreign authorship into
  postern's history, and would put an old `feat:` commit where release-please
  looks for releasable commits.
- The old repository is archived (read-only), not deleted.

**`.gitignore`: nested, not merged.** `web/site/.gitignore` is kept verbatim,
and the root `.gitignore` does not change. Git applies a nested `.gitignore` to
its own directory, so the site's `node_modules/`, `dist/` and `.astro/`
patterns stay scoped to it and travel with it. Nothing falls through: the
root's `/dist/` is anchored to the root and does not reach `web/site/dist/`,
and both files carry the same `.env` rules (`.env`, `.env.*`, `!.env.example`).

**Checks already run against the import source:**

- gitleaks 8.30.1 with this repository's `.gitleaks.toml` found nothing in
  `postern-web`'s full history (all branches) or in the imported tree.
- The banned-strings gate scans only `*.go`, `*.yaml` and `*.yml`, and the site
  has none of those today. Its copy names the vendors with a trademark notice,
  as `README.md` does, so `web/site/` joins the gate's user-facing exemptions.
- `npm ci` with install scripts disabled, then `npm run build`, passes on Node
  22.23.3 and 24.21.0. `npm audit signatures` verifies all 381 installed
  packages.
- `node_modules/` contains no `.go` files and 11 YAML files.

**Decisions for the maintainer before Stage 3.** The import publishes a
private repository:

1. **License.** `postern-web` has no license. Once imported it falls under the
   root Apache-2.0 `LICENSE`: site code, copy, and the logo/favicon SVG.
   Apache-2.0 grants no trademark rights (section 6), so the mark itself stays
   reserved. Nothing third-party is vendored; fonts load from Google Fonts at
   runtime.
2. **Known advisories.** `npm audit --omit=dev` on the lockfile reports 1
   critical, 16 high and 7 moderate: astro 4.16 (fixed only in 7.x),
   tailwindcss 3.4 (no 3.x fix) and their build toolchain. All of them are
   build-time or dev-server packages; the built site is one HTML page, one CSS
   file and a favicon. With Dependabot alerts enabled, they show up as alerts
   on this repository after the import. Recommendation: import as-is, because the
   import must stay a pure move to stay reviewable, and land the Astro and
   Tailwind upgrade as the first site PR afterwards. Add
   `npm audit --omit=dev --audit-level=high` to the `site` job once that
   upgrade is in.

## Releases and versioning

**Decision: one released component today.**

- **Backend: unchanged.** The release-please package `"."` keeps
  `release-type: go`, and the top-level `include-component-in-tag: false` keeps
  the tags at `vX.Y.Z`. The one change:

  ```json
  "packages": {
    ".": {
      "exclude-paths": ["web/site"]
    }
  }
  ```

  release-please assigns every commit in the repository to the root package.
  `exclude-paths` drops a commit when all of its files are under `web/site/`
  (upstream `src/util/commit-exclude.ts`). A site-only commit then neither bumps
  the backend version nor appears in `CHANGELOG.md`; a commit that touches both
  still counts. The exclusion names `web/site`, not `web`, because the app may
  ship inside the binary, and then its changes are backend changes.
- **Site: unversioned.** It is not a release-please package, and its
  `package.json` `version` is inert. CI builds it on every site change; once
  hosting is chosen, its own workflow deploys it from `main`.
- **App: decided by its design** ([The reserved app home](#the-reserved-app-home)).

**Why not one version for everything:** a copy edit on the site would cut a
signed, multi-platform binary release and add an entry to the binary's
changelog.

**Why the site is not a second release-please component with its own tags,
yet:**

1. release-please creates GitHub releases without setting `make_latest`
   (upstream `src/github-api.ts`), so GitHub marks each new release as Latest.
   `install.sh` installs whatever is Latest (`install.sh:27`). After a site
   release it would ask for an archive named after the site's tag, which does
   not exist, and fail for every user until the next backend release.
2. When one release PR covers two components, both tags land on the same
   commit. goreleaser takes its version from a tag pointing at HEAD and fails
   to parse a tag that is not semver. Excluding tags by prefix or glob
   (`ignore_tag_prefixes`, glob patterns in `ignore_tags`) is a GoReleaser Pro
   feature; in the open-source build the fix is pinning
   `GORELEASER_CURRENT_TAG`.
3. Nothing consumes site versions.

If a web component ever needs versions, three changes come first: a package
entry for it with `include-component-in-tag: true`; `GORELEASER_CURRENT_TAG`
pinned to release-please's root `tag_name` in both goreleaser jobs; and
`install.sh` selecting the newest `v*` release explicitly instead of Latest.
`release.yml`'s gate is already safe: the action's `release_created` output
covers only the root component.

**Invariant:** until those three changes land, every tag and every GitHub
release in this repository is a backend `vX.Y.Z`.

**Commit types for the migration itself.** Each stage's PR title (the squash
commit) uses a type that release-please does not release: `build`, `ci`,
`docs` or `chore`. Stage 3 touches root files as well as `web/site/`, so
`exclude-paths` does not cover it, and a `feat(site): …` title would cut
v0.11.0 of the binary.

## The reserved app home

Fixed now:

- The path, `web/app/`, and the contract: a self-contained npm project, like
  the site. `go.mod`'s `ignore` and `.dockerignore` already cover it.
- Its CI job, classifier branch, Dependabot entry and `app-*` Makefile targets
  follow the site's pattern.

Decided by the app's own design, and it sets the app's release model: does the
binary serve the app, or is the app hosted separately?

- **Served by the binary** (the usual shape for a Go daemon's UI, as in
  Prometheus, Vault and Traefik). The app ships inside the backend release, so
  its changes are backend changes: `web/app/` does not join `exclude-paths` or
  the classifier's skip rule. The built assets reach the binary through
  `go:embed` from a Go package outside `web/`, because embed patterns cannot
  reach outside the embedding package's directory. The release workflow must
  build the assets in a separate job with no write or OIDC permissions and hand
  the privileged goreleaser job a plain build artifact. npm code never runs in
  a job that can sign or publish postern.
- **Hosted separately.** The app is treated like the site: unversioned and
  deployed from `main`. If it needs versions, it becomes a release-please
  component only after the three changes in
  [Releases and versioning](#releases-and-versioning).

A frontend that manages postern needs a threat-model review before any API is
exposed to it. The admin listener is loopback-only by validation
([`proxy.admin_listen`](configuration.md#proxyadmin_listen)), and a management
UI widens that surface.

## Execution checklist

Each stage is one issue and one squash-merged PR, landed in order. "Green"
means every CI job that runs on the PR passes, and nothing listed as unchanged
changes.

### Stage 2: make the root safe for web components (no file moves)

PR title: `build: prepare the repository root for web components`

1. `go.mod`: add `ignore ./web`.
2. `release-please-config.json`: add `"exclude-paths": ["web/site"]` to the
   `"."` package.
3. `scripts/check-banned-strings.sh`: make the whole-tree mode filter
   `git ls-files` output through `is_exempt`/`is_scannable`, and add
   `web/site/*` to `is_exempt`.
4. `.dockerignore`: add `web/`.
5. `.github/workflows/ci.yml`: add `changes`, the Go-job gates, and `ci-ok`
   without `site` ([CI](#ci)).

No Go file moves, so there is nothing to `git mv`.

Green and unchanged:

- Every existing CI job runs and passes; the PR touches only root files.
- `make ci` and `make snapshot` pass in the devcontainer. `go list ./...`
  still lists 17 packages. `go.sum` and `THIRD_PARTY_NOTICES.md` do not
  change.
- The banned-strings script still fails on a brand string planted in a `.go`
  file, in both modes.
- After the merge, no tag or release is created, and an open release PR gains
  no entries.

Prove the classifier before Stage 3: a throwaway PR that adds only
`web/site/.probe` shows every Go job skipped and `ci-ok` green (close it
unmerged), and a PR that touches any root file still runs every job.

### Stage 3: import the site

PR title: `build(site): import postern-web at e4ca727`

Prerequisite: the maintainer's two decisions under
[Folding in postern-web](#folding-in-postern-web).

1. Commit 1: the snapshot of `postern-web@e4ca727` in `web/site/`,
   byte-for-byte.
2. Commit 2: in `web/site/package.json`, `"name": "postern-site"` and
   `"private": true`; add `web/site/.npmrc` with `ignore-scripts=true`; add
   `web/README.md`, indexing `site/` and reserving `app/`.
3. `.mise.toml`: add `node = "24.21.0"`. `ci.yml`: add
   `NODE_VERSION: "24.21.0"`, the `site` job, and `site` in `ci-ok`'s `needs`.
4. `Makefile`: `site-install`, `site-dev` (the Astro dev server on 4321, run
   with `--host` so the forwarded port reaches it), `site-build` and
   `site-ci`, all through `$(RUN)`.
5. `.devcontainer/devcontainer.json`: forward 4321, and add the Astro VS Code
   extension.
6. `.github/dependabot.yml`: the `npm` entry for `/web/site`.

Green and unchanged:

- `gitleaks` (full history, now including the import), every Go job, `site`
  and `ci-ok`.
- In the devcontainer, `make ci` behaves as before and `make site-ci` passes.
  With `web/site/node_modules/` populated, `go list ./...` still lists 17
  packages.
- After the merge, no backend release is cut, because the PR type is not
  releasable.

### Stage 4: document the monorepo and retire postern-web

PR title: `docs: document the monorepo layout`

1. `README.md`: the three components and where each lives, a short site
   section, and a link to this document.
2. `CONTRIBUTING.md`: the site workflow through `make site-*`; how CI decides
   what runs; and keeping site changes in site-only PRs. A PR that touches the
   site and root files together is a backend change to release-please, so give
   it a non-releasable type.
3. `CLAUDE.md`: `web/` in "Project layout", the `site-*` targets in
   "Commands", and three entries in "Things never to do": run npm in
   `release.yml`; put Go code under `web/`; create a tag or GitHub release that
   is not a backend `vX.Y.Z`.
4. `web/site/README.md`: container-first instructions through `make site-*`
   instead of host Node.
5. This document: set the status to implemented.
6. Maintainer: archive `mmartinez/postern-web`, and close its PR #2 as
   superseded.

Green: CI as for any documentation PR, and every relative link resolves.

### After the restructure

These are follow-ups, not part of the three stages:

- Upgrade the site's dependencies (Astro 4 to 7, Tailwind 3 to 4), then add the
  advisory gate to the `site` job.
- Fix content drift on the site: its hero and status copy still say "Linux
  amd64/arm64 only", although darwin builds have shipped since #85.
- Choose hosting for the site and add its deploy workflow, under the
  constraints in [CI](#ci).
- Make `ci-ok` the required status check in the `main` ruleset.
- When the app starts, settle its serving model first; see
  [The reserved app home](#the-reserved-app-home).
