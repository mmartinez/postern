# Web components

Web frontends live under this directory, one self-contained npm project per component.
Each has its own `package.json`, lockfile and build; there is no root npm project.

| Component | Path | What it is |
|---|---|---|
| site | `site/` | Marketing landing page served at postern.dev (Astro + Tailwind). |
| app | `app/` (reserved) | The postern app web frontend, created by the app's first pull request. |

## Commands

Run these from the repository root; like every other target they go through the
devcontainer.

| Target | What it does |
|---|---|
| `make site-install` | Install the site's dependencies from `web/site/package-lock.json`. |
| `make site-dev` | Astro dev server on port 4321, reachable from the host through the forwarded port. |
| `make site-build` | Static build into `web/site/dist/`. |
| `make site-ci` | What CI runs: clean install, then build. |

## Adding a component

A new component is a new directory here with its own `package.json`, lockfile, `.gitignore` and build.
Give it its own Dependabot entry, CI job, branch in the CI `changes` classifier, and `make <name>-*` targets.
`go.mod`'s `ignore ./web` and the root `.dockerignore` already cover everything under `web/`.

Web components are unversioned.
Every tag and GitHub release in this repository is a backend `vX.Y.Z`: `install.sh` installs whichever release is marked Latest, and goreleaser fails on a tag that is not semver.
A component that deploys gets its own workflow file, triggered by changes under its path on `main` and holding only the permissions its host needs.

`app/` is reserved but not created: an npm project without a `package.json` breaks tools that look for one, Dependabot among them.
If the binary serves the app, its changes are backend changes: keep `web/app` out of release-please's `exclude-paths` and the classifier's skip rule, and build its assets in a job with no write or OIDC permissions.
