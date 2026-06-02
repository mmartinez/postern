#!/usr/bin/env bash
# Verifies a built postern release image. Unlike the other scripts/ tools this
# runs on the host / CI runner (it needs the Docker daemon), not inside the
# devcontainer.
#
# Asserts:
#   1. the image runs as the non-root uid 65532,
#   2. the entrypoint works (postern --version),
#   3. no service-account token is baked into the image env or layer history.
#
# Usage: scripts/verify-release-image.sh <image-ref> [--no-run]
#   --no-run  skip the --version check (use for a non-native arch image that
#             cannot execute on this runner without emulation).
set -euo pipefail

img="${1:?usage: verify-release-image.sh <image-ref> [--no-run]}"
run=1
[ "${2:-}" = "--no-run" ] && run=0

fail() {
    echo "FAIL ($img): $1" >&2
    exit 1
}

# 1. Non-root uid.
user="$(docker inspect --format '{{.Config.User}}' "$img")"
[ "$user" = "65532:65532" ] || fail "expected user 65532:65532, got '${user}'"

# 2. Entrypoint works (native-arch images only).
if [ "$run" -eq 1 ]; then
    docker run --rm "$img" --version >/dev/null || fail "--version did not run"
fi

# 3. No credential material baked in. The service-account token shape is
# ops_<base64-ish>; fail closed if that literal appears in the image env or in
# any layer's build command.
env_json="$(docker inspect --format '{{json .Config.Env}}' "$img")"
history="$(docker history --no-trunc --format '{{.CreatedBy}}' "$img")"
if printf '%s\n%s\n' "$env_json" "$history" | grep -Eq 'ops_[A-Za-z0-9_-]{8,}'; then
    fail "a service-account token shape (ops_...) is present in the image env or history"
fi

echo "OK ($img): uid 65532, entrypoint ok, no baked credentials"
