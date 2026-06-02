# tint (vendored)

This directory contains a verbatim copy of
[github.com/lmittmann/tint](https://github.com/lmittmann/tint) at tag
[`v1.1.3`](https://github.com/lmittmann/tint/releases/tag/v1.1.3), licensed
under MIT. The upstream `LICENSE` is preserved in this directory.

We vendor the source rather than pulling tint in via `go.mod` so the
postern binary keeps a single minimal-dependency footprint. The package is
excluded from `golangci-lint` (`.golangci.yml`) and from project-style
gates because it is third-party code we do not maintain — upstream is the
authoritative source for fixes. To upgrade, replace `handler.go` and
`buffer.go` from the new upstream tag and refresh `LICENSE` if its content
changes.

Attribution also appears in `THIRD_PARTY_NOTICES.md` at the repo root.
