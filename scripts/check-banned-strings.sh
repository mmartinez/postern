#!/usr/bin/env bash
# Hard rule: no vendor brand literals in source/config files.
# Files that define the gate (this script, lefthook config, gitleaks config,
# CI workflows) necessarily contain those strings and are exempt — so are
# user-facing docs (NOTICE, LICENSE, README, docs/) and the internal SDK
# wrapper directory whose entire purpose is to encapsulate the vendor brand
# coupling (internal/credstore/onepassword/).
#
# Usage:
#   scripts/check-banned-strings.sh [file ...]
#
# With no args, scans the tracked tree. With args, scans only those files
# (used by lefthook pre-commit with the staged file list).
set -euo pipefail

banned='1[ -]?password|infisical|agent[ -]?vault'

is_exempt() {
    case "$1" in
        NOTICE|LICENSE|README.md|THIRD_PARTY_NOTICES.md) return 0 ;;
        lefthook.yml|.gitleaks.toml) return 0 ;;
        docs/*|.github/*|scripts/check-banned-strings.sh) return 0 ;;
        internal/credstore/onepassword/*) return 0 ;;
        web/site/*) return 0 ;;
        *) return 1 ;;
    esac
}

is_scannable() {
    case "$1" in
        *.go|*.yaml|*.yml) return 0 ;;
        *) return 1 ;;
    esac
}

hits=0

select_files() {
    while IFS= read -r -d '' f; do
        if is_exempt "$f"; then continue; fi
        if ! is_scannable "$f"; then continue; fi
        printf '%s\0' "$f"
    done
}

if [ $# -eq 0 ]; then
    # Whole-tree scan (CI mode): tracked paths only, so untracked npm trees
    # (web/site/node_modules/) are never read.
    tmp=$(mktemp)
    trap 'rm -f "$tmp"' EXIT
    if ! git ls-files -z >"$tmp"; then
        echo "banned strings: cannot list tracked files (git ls-files failed)" >&2
        exit 1
    fi
    mapfile -d '' -t files < <(select_files <"$tmp")
else
    mapfile -d '' -t files < <(printf '%s\0' "$@" | select_files)
fi

if [ ${#files[@]} -gt 0 ]; then
    out=$(printf '%s\0' "${files[@]}" | xargs -0 grep -EIn -i -E "$banned" -- || true)
    if [ -n "$out" ]; then
        printf '%s\n' "$out"
        hits=1
    fi
fi

if [ "$hits" -ne 0 ]; then
    echo
    echo "banned brand strings found — vendor brand literals are not allowed in tracked source/config"
    exit 1
fi
