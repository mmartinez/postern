# syntax=docker/dockerfile:1.7

# Postern devcontainer — debian:bookworm-slim + mise.
# All Go/lint/test tooling is installed by mise from .mise.toml inside the
# image (or at postCreateCommand time), so the host needs only Docker + git +
# the devcontainer CLI.

FROM debian:bookworm-slim

# UID/GID provided by devcontainer.json updateRemoteUserUID; defaults match
# typical Linux dev hosts. Pinning them keeps file ownership on bind mounts
# from drifting.
ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=1000

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Base packages: just enough to bootstrap mise and run a sane shell.
# - git: for the in-container git workflow (lefthook hooks run here).
# - build-essential: cgo + gnome-keyring builds need a C toolchain.
# - libsecret-1-dev: required by 99designs/keyring for the Secret Service
#   integration test (the test self-skips if D-Bus is absent).
# - pkg-config: libsecret cgo wrapper expects it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        make \
        build-essential \
        libsecret-1-dev \
        pkg-config \
        unzip \
        xz-utils \
        zstd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with the requested UID/GID.
RUN groupadd --gid "${USER_GID}" "${USERNAME}" \
    && useradd  --uid "${USER_UID}" --gid "${USER_GID}" --shell /bin/bash --create-home "${USERNAME}"

# Install mise globally (system-wide binary, per-user activation).
# Pinned via the official install script + checksum.
ENV MISE_VERSION=v2025.1.0
RUN curl -fsSL https://mise.run | MISE_INSTALL_PATH=/usr/local/bin/mise sh \
    && mise --version

USER ${USERNAME}
WORKDIR /workspaces/postern

# Activate mise for interactive shells.
RUN echo 'eval "$(/usr/local/bin/mise activate bash)"' >> /home/${USERNAME}/.bashrc \
    && echo 'export PATH=/home/'${USERNAME}'/.local/share/mise/shims:$PATH' >> /home/${USERNAME}/.bashrc

# Cache mounts target these — pre-create so volume mount points are owned by dev.
RUN mkdir -p /home/${USERNAME}/go/pkg/mod /home/${USERNAME}/.cache/go-build

# Default to an interactive bash login when the container is exec'd into.
SHELL ["/bin/bash", "-lc"]
CMD ["sleep", "infinity"]
