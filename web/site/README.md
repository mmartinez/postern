# postern-web

Marketing site for [Postern](https://github.com/mmartinez/postern) — a credential-brokering HTTPS proxy for AI agents.

Built with [Astro](https://astro.build) and [Tailwind CSS](https://tailwindcss.com).

## Prerequisites

- Node.js 18+
- npm (or pnpm / yarn)

## Local development

```sh
npm install
npm run dev
```

The dev server starts at `http://localhost:4321` with hot-module replacement.

## Build

```sh
npm run build
```

Output goes to `dist/`. The build is fully static — drop it behind any CDN or static hosting (Netlify, Vercel, Cloudflare Pages, GitHub Pages, etc.).

## Preview production build

```sh
npm run preview
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
