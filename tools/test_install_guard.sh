#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Checks for the scx_flow installer.
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${REPO_DIR}/scx"
INST="${REPO_DIR}/tools/install_scx_flow.sh"
CI="${REPO_DIR}/.github/workflows/ci.yml"

fail() {
    echo "guard test failed: $1" >&2
    exit 1
}

[ -f "${INST}" ] || fail "installer missing"
[ -f "${SRC_DIR}/Cargo.toml" ] || fail "cargo manifest missing"

# The installer builds the version the manifest declares.
want="$(grep '^version' "${SRC_DIR}/Cargo.toml" | head -n 1 | cut -d '"' -f 2)"
got="$(grep '^VER=' "${INST}" | head -n 1 | cut -d '"' -f 2)"
[ "${want}" = "${got}" ] || fail "installer builds ${got}, manifest says ${want}"

# The installer and CI build against the same pinned workspace commit.
inst_ref="$(grep '^SCX_REF=' "${INST}" | cut -d '"' -f 2)"
ci_ref="$(grep 'SCX_REF:' "${CI}" | head -n 1 | awk '{print $2}')"
printf '%s' "${inst_ref}" | grep -qE '^[0-9a-f]{40}$' || fail "workspace commit not pinned"
[ "${inst_ref}" = "${ci_ref}" ] || fail "installer pins ${inst_ref}, CI pins ${ci_ref}"
grep -q '^FORK="https://github.com/galpt/scx"$' "${INST}" || fail "fork remote changed"

# A bad workspace path must be refused before anything is fetched or
# removed, with the reason on stderr only. The checks run a copy of the
# installer in which removing, fetching and installing only print what
# they would do, so a guard that lets a path through cannot harm it.
SAFE_INST="$(mktemp /tmp/scx-guard-inst-XXXXXX)"
link_dir="$(mktemp -d /tmp/scx-guard-XXXXXX)"
trap 'rm -rf -- "${link_dir}" "${SAFE_INST}"' EXIT
sed -e 's/^\( *\)rm -rf -- /\1echo rm -rf -- /' \
    -e 's/^\( *\)mkdir -p -- /\1echo mkdir -p -- /' \
    -e 's/^: > /echo : > /' \
    -e 's/^git /echo git /' \
    -e 's/^if ! git /if ! echo git /' \
    -e 's/^\( *\)rsync /\1echo rsync /' \
    -e 's/^\( *\)rm -f -- /\1echo rm -f -- /' \
    -e 's/^\( *\)ln -s /\1echo ln -s /' \
    -e 's/^cargo /echo cargo /' \
    -e 's/^if ! install /if ! echo install /' \
    "${INST}" >"${SAFE_INST}"
for line in 'echo rm -rf -- "${WS}"' 'if ! echo install ' 'echo git -C "${WS}" checkout'; do
    grep -qF "${line}" "${SAFE_INST}" || fail "could not neutralize: ${line}"
done
if grep -qE '^ *(rm -rf|install -m|git -C|cargo build)' "${SAFE_INST}"; then
    fail "the installer copy still removes, fetches or installs"
fi

check_refuse() {
    local path="$1"
    local label="$2"
    local err
    local out
    local err_file
    err_file="$(mktemp)"
    if out="$(bash "${SAFE_INST}" "${path}" 2>"${err_file}")"; then
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
check_refuse "/tmp/opencode" "tmp dir outside the allowlist"
check_refuse "/tmp/opencode/scx" "tmp subdir outside the allowlist"
check_refuse "/tmp" "tmp root"
check_refuse "/tmp/other" "tmp non allowlisted"
check_refuse "/tmp/scx-workspace/../opencode" "dotdot out of the allowlist"
check_refuse "/home" "home root"
check_refuse "/home/user/ws" "home tree"
check_refuse "/usr" "usr root"
check_refuse "/usr/local/ws" "usr tree"
check_refuse "/var" "var root"
check_refuse "/var/tmp/ws" "var tree"
check_refuse "/etc" "etc root"
check_refuse "/boot" "boot root"
check_refuse "/opt" "opt root"
check_refuse "/srv" "srv root"
check_refuse "/root" "root home"
check_refuse "/mnt/x" "mnt tree"
check_refuse "/mnt/data" "mnt data"
if [ -n "${HOME:-}" ]; then
    check_refuse "${HOME}" "home env root"
    check_refuse "${HOME}/ws" "home env tree"
fi

# A symlink is judged by its target, so a link under /tmp/scx-* that
# points outside the allowed workspaces is refused, as the workspace or as
# one of its parents.
ln -s /var/tmp/scx-guard-target "${link_dir}/link"
ln -s /usr/share "${link_dir}/parent"
check_refuse "${link_dir}/link" "symlink into /var"
check_refuse "${link_dir}/parent/ws" "symlinked parent into /usr"

echo "installer guard checks passed"
