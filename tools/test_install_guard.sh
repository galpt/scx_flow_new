#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Guard checks for the flow installer.
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_DIR}/scx"
INST="${REPO_DIR}/tools/install_scx_flow.sh"

fail() {
    echo "guard test failed: $1" >&2
    exit 1
}

[ -f "${INST}" ] || fail "installer missing"
[ -f "${SRC_DIR}/Cargo.toml" ] || fail "cargo manifest missing"

# Version stays in sync between installer plus manifest.
want="$(grep '^version' "${SRC_DIR}/Cargo.toml" | head -n 1 | cut -d '"' -f 2)"
got="$(grep '^VER=' "${INST}" | head -n 1 | cut -d '"' -f 2)"
[ "${want}" = "${got}" ] || fail "version mismatch got ${want} want ${got}"
[ "${want}" = "4.7.6" ] || fail "version not at 4.7.6"

# Newline plus tab use ANSI-C quoting with no command substitution.
grep -q "^NL=\$'\\\\n'$" "${INST}" || fail "NL guard form bad"
grep -q "^TAB=\$'\\\\t'$" "${INST}" || fail "TAB guard form bad"

# Shared CI tree stays protected with no clean.
grep -q "/tmp/opencode" "${INST}" || fail "opencode guard missing"

# Canonical plus allowlist guards stay present. The -m forms stay for
# string canonicalization plus a symlink refuse covers the resolve gap.
grep -q "realpath -m" "${INST}" || fail "realpath guard missing"
grep -q "readlink -m" "${INST}" || fail "readlink fallback missing"
grep -q '\[ -L "${WS}" \]' "${INST}" || fail "symlink guard missing"
grep -q 'rm -rf --' "${INST}" || fail "rm dash guard missing"
grep -q "/tmp/scx-" "${INST}" || fail "allowlist guard missing"
grep -q "/home | /home" "${INST}" || fail "home guard missing"
grep -q "/usr | /usr" "${INST}" || fail "usr guard missing"
grep -q "/var | /var" "${INST}" || fail "var guard missing"

# Each bad workspace path fails closed before any fetch with a refusing
# note on stderr and no refusing text on stdout, so silent drops plus
# stdout leaks never pass. Stderr plus stdout stay split, so a script
# that prints refusing to stdout still fails the stderr assert.
check_refuse() {
    local path="$1"
    local label="$2"
    local err
    local out
    local err_file
    err_file="$(mktemp)"
    if out="$(bash "${INST}" "${path}" 2>"${err_file}")"; then
        rm -f "${err_file}"
        fail "accepted bad path ${label}"
    fi
    err="$(cat "${err_file}")"
    rm -f "${err_file}"
    case "${err}" in
        *refusing*)
            ;;
        *)
            fail "missing refusing text on stderr for ${label}: ${err}"
            ;;
    esac
    case "${out}" in
        *refusing*)
            fail "refusing text leaked to stdout for ${label}: ${out}"
            ;;
    esac
}

check_refuse "/" "root"
check_refuse "//" "double root"
check_refuse "relative/path" "relative"
check_refuse "/tmp/with space" "space"
check_refuse "/tmp/with*glob" "glob"
check_refuse "/tmp/opencode" "opencode root"
check_refuse "/tmp/opencode/scx" "opencode tree"
check_refuse "/tmp" "tmp root"
check_refuse "/tmp/other" "tmp non allowlisted"
check_refuse "/tmp/scx-workspace/../opencode" "dotdot escape"
check_refuse "/home" "home root"
check_refuse "/home/user/ws" "home tree"
check_refuse "/usr" "usr root"
check_refuse "/usr/local/ws" "usr tree"
check_refuse "/var" "var root"
check_refuse "/var/tmp/ws" "var tree"
if [ -n "${HOME:-}" ]; then
    check_refuse "${HOME}" "home env root"
    check_refuse "${HOME}/ws" "home env tree"
fi

echo "guard tests passed"
