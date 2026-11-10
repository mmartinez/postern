# Postern Makefile.
#
# Targets are dual-mode:
#   - Inside the devcontainer: invoked directly (go, golangci-lint, etc).
#   - On the host: wrapped with `devcontainer exec --workspace-folder .`.
#
# Detection: presence of /.dockerenv (set by Docker) OR the explicit
# POSTERN_IN_CONTAINER=1 env var (escape hatch for non-Docker envs like CI).

SHELL := /bin/bash

ifeq ($(wildcard /.dockerenv),)
ifneq ($(POSTERN_IN_CONTAINER),1)
  IN_CONTAINER := 0
else
  IN_CONTAINER := 1
endif
else
  IN_CONTAINER := 1
endif

ifeq ($(IN_CONTAINER),1)
  RUN :=
else
  RUN := devcontainer exec --workspace-folder . --
endif

# Default goal — show help.
.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*##"; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: up
up: ## Start the devcontainer (host only).
	devcontainer up --workspace-folder .

.PHONY: down
down: ## Stop and remove the devcontainer (host only).
	devcontainer down --workspace-folder . || true

.PHONY: shell
shell: ## Open an interactive shell inside the devcontainer.
ifeq ($(IN_CONTAINER),1)
	@echo "already inside devcontainer"; exec /bin/bash -l
else
	devcontainer exec --workspace-folder . /bin/bash -l
endif

.PHONY: fmt
fmt: ## Format Go code with gofumpt.
	$(RUN) gofumpt -extra -w .

.PHONY: lint
lint: ## Run golangci-lint.
	$(RUN) golangci-lint run ./...

.PHONY: test
test: ## Run the full Go test suite with coverage.
	$(RUN) go test -race -coverprofile=coverage.out -covermode=atomic ./...

.PHONY: vuln
vuln: ## Run govulncheck against all packages.
	$(RUN) govulncheck ./...

.PHONY: licenses
licenses: ## Regenerate THIRD_PARTY_NOTICES.md from current go.sum.
	$(RUN) bash scripts/gen-third-party-notices.sh

.PHONY: publication
publication: ## Check public content and publication guard behavior.
	$(RUN) node --test scripts/check-publication.test.mjs
	$(RUN) node scripts/check-publication.mjs

.PHONY: ci
ci: publication lint test vuln licenses ## Run the full CI pipeline locally.

# Web components. One target set per component; the app gets app-* targets
# when it exists.
.PHONY: site-install
site-install: ## Install the site's dependencies from its lockfile.
	$(RUN) npm --prefix web/site ci

.PHONY: site-dev
site-dev: ## Run the site dev server on port 4321.
	$(RUN) npm --prefix web/site run dev -- --host

.PHONY: site-build
site-build: ## Build the static site into web/site/dist.
	$(RUN) npm --prefix web/site run build

.PHONY: site-ci
site-ci: ## Install, verify signatures, audit, and build the site the way CI does.
	$(RUN) npm --prefix web/site ci
	$(RUN) npm --prefix web/site audit signatures
	$(RUN) npm --prefix web/site audit --audit-level=high
	$(RUN) npm --prefix web/site run build

.PHONY: build
build: ## Build the postern binary.
	$(RUN) go build -o dist/postern ./cmd/postern

.PHONY: snapshot
snapshot: ## Build a local release snapshot (cross-compiled binaries, archives, checksums, SBOMs; no docker/publish/sign).
	# --skip=docker: the devcontainer has no Docker daemon (the image is built
	# and verified by the snapshot CI job). --skip=sign: --snapshot does not
	# imply it, and there is no cosign/OIDC locally.
	$(RUN) goreleaser release --snapshot --clean --skip=docker,sign
