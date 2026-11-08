# postern-site

Marketing site for [Postern](https://github.com/mmartinez/postern) — a credential-brokering HTTPS proxy for AI agents.

Built with [Astro](https://astro.build) and [Tailwind CSS](https://tailwindcss.com).

This is one of the repository's web components; see [web/README.md](../README.md) for how the monorepo is organized.

## Prerequisites

None beyond the repository's container-first setup: Node is pinned in `.mise.toml` and
installed inside the devcontainer.

`.npmrc` sets `ignore-scripts=true`, so no dependency install script runs, in CI or in the devcontainer.
If a dependency really needs its script, run `npm rebuild <pkg>` for that one package instead of turning scripts back on.

## Local development

Run from the repository root:

```sh
make site-install   # install dependencies from package-lock.json
make site-dev       # Astro dev server on http://localhost:4321
```

The dev server runs with hot-module replacement, on a port the devcontainer forwards.

## Build

```sh
make site-build
```

Output goes to `dist/`, relative to this directory. The build is fully static — drop it behind any CDN or static hosting (Netlify, Vercel, Cloudflare Pages, GitHub Pages, etc.). `make site-ci` runs what CI runs: a clean install, the registry signature check, the advisory audit, then the build.

## Preview production build

Inside a container shell (`make shell`):

```sh
cd web/site && npm run preview
```

Serves the `dist/` output at `http://localhost:4321`.

## Project structure

```
src/
  layouts/Layout.astro   Base HTML shell, meta tags, font loading
  pages/index.astro      Landing page (single page)
public/
  favicon.svg
```

## Deploy

The site is static. Any host that serves a folder works:

```sh
# Netlify CLI
netlify deploy --dir=dist --prod

# Vercel CLI
vercel --prod

# Or just copy dist/ to your server
```
