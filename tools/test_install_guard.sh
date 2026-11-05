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
[ "${want}" = "5.0.10" ] || fail "version not at 5.0.10"

# Scheduler sources stay present with no empty scaffold.
# A scaffold with matching version but no logic fails closed here.
for need_file in \
    "src/bpf/main.bpf.c" \
    "src/bpf/intf.h" \
    "src/main.rs" \
    "src/stats.rs" \
    "build.rs"; do
    [ -s "${SRC_DIR}/${need_file}" ] || fail "scaffold missing ${need_file}"
done

# Vendored lib stays present with no empty lib dir.
for need_lib in \
    "src/bpf/lib/common.bpf.c" \
    "src/bpf/lib/dhq.bpf.c"; do
    [ -s "${SRC_DIR}/${need_lib}" ] || fail "lib scaffold missing ${need_lib}"
done

# Docs stay present as additive narrative with no knob change.
for need_doc in \
    "docs/lifecycle.md" \
    "docs/verifier-budgets.md"; do
    [ -s "${REPO_DIR}/${need_doc}" ] || fail "docs scaffold missing ${need_doc}"
done

# Top README keeps lifecycle plus budgets plus reinstall plus kernel plus lock notes.
for need_note in \
    "## Lifecycle" \
    "## Verifier budgets" \
    "## Reinstall safety" \
    "## Kernel support" \
    "## Cargo lock note"; do
    grep -qF "${need_note}" "${REPO_DIR}/README.md" || fail "readme note missing ${need_note}"
done

# Flow headers stay present with timeless rationale and no logic drift.
# Code comments stay version-agnostic like lavd plain prose: no X.Y.Z
# in src/bpf plus build.rs. Version lives only in Cargo plus installer
# plus guard plus CHANGELOG plus manifest.
for need_flow in \
    "src/bpf/flow/cgroup.bpf.h" \
    "src/bpf/flow/dispatch.bpf.h" \
    "src/bpf/flow/enqueue.bpf.h" \
    "src/bpf/flow/freq.bpf.h" \
    "src/bpf/flow/guards.bpf.h" \
    "src/bpf/flow/lifecycle.bpf.h" \
    "src/bpf/flow/maps.bpf.h" \
    "src/bpf/flow/preempt.bpf.h" \
    "src/bpf/flow/stats.bpf.h" \
    "src/bpf/flow/steal.bpf.h" \
    "src/bpf/flow/vtime.bpf.h"; do
    [ -s "${SRC_DIR}/${need_flow}" ] || fail "flow scaffold missing ${need_flow}"
    grep -q "Docs only, no logic change." "${SRC_DIR}/${need_flow}" || fail "flow rationale missing ${need_flow}"
done

# Main plus intf plus build keep timeless rationale with no logic change.
for need_core in \
    "src/bpf/main.bpf.c" \
    "src/bpf/intf.h" \
    "build.rs"; do
    grep -q "Docs only" "${SRC_DIR}/${need_core}" || fail "core rationale missing ${need_core}"
done

# BPF plus build stay version-agnostic with no X.Y.Z string.
if grep -rnE "[0-9]+\.[0-9]+\.[0-9]+" "${SRC_DIR}/src/bpf" "${SRC_DIR}/build.rs" 2>/dev/null; then
    fail "version string in BPF comment"
fi

# Scheduler README stays byte identical with no doc drift.
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "0d40abdd36be0c7b3393c8c45ffc86fdcb42b16ba6c73c704de206523dd2495a" ] || fail "scx README drifted"
[ "$(wc -l < "${SRC_DIR}/README.md" | tr -d ' ')" = "17" ] || fail "scx README lines drifted"

# Harness stays present with no logic change.
[ -s "${REPO_DIR}/tools/edf_harness/harness.c" ] || fail "harness scaffold missing harness.c"
[ -s "${REPO_DIR}/tools/edf_harness/run.sh" ] || fail "harness scaffold missing run.sh"

# Changelog stays present with the additive 5.0.10 entry.
[ -s "${REPO_DIR}/CHANGELOG.md" ] || fail "changelog scaffold missing"
grep -q "5\.0\.10" "${REPO_DIR}/CHANGELOG.md" || fail "changelog version missing"

# Deleted Rust mirrors stay deleted with no reappearance.
# The flow facade plus its helpers stay deleted with constants in
# config.rs, so any return fails closed here before any build.
for gone in \
    "src/rust/flow/mod.rs" \
    "src/rust/flow/cgrp.rs" \
    "src/rust/flow/dispatch.rs" \
    "src/rust/flow/edf.rs" \
    "src/rust/flow/lifecycle.rs" \
    "src/rust/flow/preempt.rs" \
    "src/rust/flow/property.rs" \
    "src/rust/flow/select.rs" \
    "src/rust/flow/slice.rs" \
    "src/rust/flow/slot.rs" \
    "src/rust/flow/timer.rs" \
    "src/rust/flow/vtime.rs" \
    "src/rust/flow/weight.rs"; do
    [ ! -e "${SRC_DIR}/${gone}" ] || fail "mirror reappeared ${gone}"
done

# Deleted property harness stays deleted with no reappearance.
[ ! -e "${REPO_DIR}/tools/edf_harness/property.sh" ] || fail "property.sh reappeared"

# Newline plus tab use ANSI-C quoting with no command substitution.
grep -q "^NL=\$'\\\\n'$" "${INST}" || fail "NL guard form bad"
grep -q "^TAB=\$'\\\\t'$" "${INST}" || fail "TAB guard form bad"

# Shared CI tree stays protected with no clean.
grep -q "/tmp/opencode" "${INST}" || fail "opencode guard missing"

# Fork remote stays pinned with no upstream drift.
grep -q 'FORK="https://github.com/galpt/scx"' "${INST}" || fail "fork remote missing"
grep -q 'pinned fork ref' "${INST}" || fail "fork pin comment missing"

# Overlay lib stays byte-identical with no silent drift.
grep -q 'cmp -s' "${INST}" || fail "lib hash check missing"
grep -q 'lib drift' "${INST}" || fail "lib drift guard missing"

# Fork keeps lib plus license as symlinks with no real copy.
grep -q 'src/bpf/lib' "${INST}" || fail "lib symlink missing"
grep -q '\.\./\.\./\.\./\.\./\.\./lib' "${INST}" || fail "lib symlink target bad"
grep -q '\.\./\.\./\.\./LICENSE' "${INST}" || fail "license symlink missing"

# Cgroup weight hooks need 6.12 plus with a parsable kernel check.
grep -q '6\.12' "${INST}" || fail "kernel guard missing"
grep -q 'uname -r' "${INST}" || fail "kernel uname guard missing"
grep -q 'cgroup weight hooks' "${INST}" || fail "kernel cgroup comment missing"

# Canonical plus allowlist guards stay present. The -m forms stay for
# string canonicalization plus a symlink refuse covers the resolve gap.
grep -q "realpath -m" "${INST}" || fail "realpath guard missing"
grep -q "readlink -m" "${INST}" || fail "readlink fallback missing"
grep -q '\[ -L "${WS}" \]' "${INST}" || fail "symlink guard missing"
grep -q 'symlinked parent' "${INST}" || fail "parent symlink guard missing"
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
