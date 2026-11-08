# Web components

Web frontends live under this directory, one self-contained npm project per component.
Each has its own `package.json`, lockfile and build; there is no root npm project.
See [docs/monorepo-layout.md](../docs/monorepo-layout.md) for the rationale and the
rules for adding a component.

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
