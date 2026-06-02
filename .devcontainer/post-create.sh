#!/usr/bin/env bash
# Devcontainer post-create hook.
# Runs once after the container is first built. Idempotent on subsequent rebuilds.
set -euo pipefail

echo "==> mise trust"
mise trust

echo "==> mise install"
mise install -y

# go install needs go on PATH; mise just put it there.
eval "$(mise activate bash)"

echo "==> go install govulncheck"
go install golang.org/x/vuln/cmd/govulncheck@latest

echo "==> go install go-licenses"
go install github.com/google/go-licenses@latest

if [ -f lefthook.yml ]; then
  echo "==> lefthook install"
  lefthook install
fi

if [ -f go.mod ]; then
  echo "==> go mod download"
  go mod download
fi

echo "==> devcontainer ready"
