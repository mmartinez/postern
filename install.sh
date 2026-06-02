#!/usr/bin/env sh
# postern installer — Linux amd64/arm64 only (macOS/Windows deferred).
#
# Downloads a release tarball and checksums.txt from GitHub, verifies the
# tarball's sha256, and installs the binary to /usr/local/bin (override with
# POSTERN_INSTALL_DIR; you may need sudo for the default location).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mmartinez/postern/main/install.sh | sh
#
# Env overrides (also the seams the test suite drives):
#   POSTERN_VERSION      release tag to install (default: latest via GitHub API)
#   POSTERN_INSTALL_DIR  install directory (default: /usr/local/bin)
#   POSTERN_OS           override detected OS (default: uname -s)
#   POSTERN_ARCH         override detected arch (default: uname -m)
#   POSTERN_BASE_URL     release download base (default: GitHub releases)
#   POSTERN_API_URL      latest-release API URL (default: GitHub API)
set -eu

OWNER=mmartinez
REPO=postern

OS="${POSTERN_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
ARCH="${POSTERN_ARCH:-$(uname -m)}"
INSTALL_DIR="${POSTERN_INSTALL_DIR:-/usr/local/bin}"
BASE_URL="${POSTERN_BASE_URL:-https://github.com/${OWNER}/${REPO}/releases/download}"
API_URL="${POSTERN_API_URL:-https://api.github.com/repos/${OWNER}/${REPO}/releases/latest}"

err() {
	echo "postern: error: $1" >&2
	exit 1
}

case "$OS" in
linux) ;;
*) err "unsupported OS '${OS}' (linux only; macOS/Windows deferred)" ;;
esac

case "$ARCH" in
x86_64 | amd64) ARCH=amd64 ;;
aarch64 | arm64) ARCH=arm64 ;;
*) err "unsupported architecture '${ARCH}' (linux amd64/arm64 only)" ;;
esac

VERSION="${POSTERN_VERSION:-}"
if [ -z "$VERSION" ]; then
	VERSION="$(curl -fsSL "$API_URL" | grep '"tag_name":' | head -1 |
		sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
	[ -n "$VERSION" ] || err "could not resolve the latest release version"
fi

# goreleaser strips the leading v from .Version, so the tag is v1.2.3 but the
# asset is postern_1.2.3_linux_amd64.tar.gz.
ASSET="postern_${VERSION#v}_${OS}_${ARCH}.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "postern: downloading ${ASSET} (${VERSION})…"
curl -fsSL -o "${tmp}/${ASSET}" "${BASE_URL}/${VERSION}/${ASSET}" ||
	err "download failed for ${ASSET}"
curl -fsSL -o "${tmp}/checksums.txt" "${BASE_URL}/${VERSION}/checksums.txt" ||
	err "download failed for checksums.txt"

echo "postern: verifying checksum…"
expected="$(awk -v f="$ASSET" '$2 == f {print $1}' "${tmp}/checksums.txt")"
[ -n "$expected" ] || err "${ASSET} is missing from checksums.txt"
actual="$(sha256sum "${tmp}/${ASSET}" | awk '{print $1}')"
[ "$expected" = "$actual" ] || err "checksum verification failed for ${ASSET}"

tar -xzf "${tmp}/${ASSET}" -C "$tmp" postern || err "could not extract postern from ${ASSET}"
mkdir -p "$INSTALL_DIR" || err "could not create ${INSTALL_DIR}"
install -m 0755 "${tmp}/postern" "${INSTALL_DIR}/postern" ||
	err "could not install to ${INSTALL_DIR} (try sudo, or set POSTERN_INSTALL_DIR)"

echo "postern: installed ${VERSION} to ${INSTALL_DIR}/postern"
