#!/usr/bin/env bash
# PRD §13.8 hard rule: no vendor brand literals in source/config files.
# Files that define the gate (this script, lefthook config, gitleaks config,
# CI workflows) necessarily contain those strings and are exempt — so are
# user-facing docs (NOTICE, LICENSE, README, docs/) and the internal SDK
# wrapper directory whose entire purpose is to encapsulate the vendor brand
# coupling (internal/onepassword/).
#
# Usage:
#   scripts/check-banned-strings.sh [file ...]
#
# With no args, scans the whole working tree. With args, scans only those
# files (used by lefthook pre-commit with the staged file list).
set -euo pipefail

banned='1[ -]?password|infisical|agent[ -]?vault'

is_exempt() {
    case "$1" in
        NOTICE|LICENSE|README.md|THIRD_PARTY_NOTICES.md) return 0 ;;
        lefthook.yml|.gitleaks.toml) return 0 ;;
        docs/*|.github/*|scripts/check-banned-strings.sh) return 0 ;;
        internal/onepassword/*) return 0 ;;
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
if [ $# -eq 0 ]; then
    # Whole-tree scan (CI mode). grep -R does its own dir walk.
    if grep -REIn -i --include='*.go' --include='*.yaml' --include='*.yml' \
        --exclude-dir=docs --exclude-dir=.github --exclude-dir=.git \
        --exclude-dir=onepassword \
        --exclude=NOTICE --exclude=LICENSE --exclude=README.md \
        --exclude=THIRD_PARTY_NOTICES.md \
        --exclude=lefthook.yml --exclude=.gitleaks.toml \
        --exclude=check-banned-strings.sh \
        -E "$banned" . ; then
        hits=1
    fi
else
    # Staged-file scan (lefthook mode). Filter the list ourselves.
    files=()
    for f in "$@"; do
        if is_exempt "$f"; then continue; fi
        if ! is_scannable "$f"; then continue; fi
        files+=("$f")
    done
    if [ ${#files[@]} -gt 0 ]; then
        if grep -EIn -i -E "$banned" "${files[@]}"; then
            hits=1
        fi
    fi
fi

if [ "$hits" -ne 0 ]; then
    echo
    echo "banned brand strings found — see PRD §13.8"
    exit 1
fi
