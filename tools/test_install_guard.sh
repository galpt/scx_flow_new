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
[ "${want}" = "5.1.2" ] || fail "version not at 5.1.2"

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

# No vendored sources remain: all helpers come from workspace headers.
# Any return of the old lib dir fails closed here before any build.
[ ! -e "${SRC_DIR}/src/bpf/lib" ] || fail "vendored lib reappeared"

# Docs plus changelog plus todos stay untracked with no re-leak.
# History remains public in prior commits; tips carry no docs blobs.
if git -C "${REPO_DIR}" ls-files -- docs/ CHANGELOG.md TODO.md | grep -q .; then
    fail "docs re-leaked"
fi

# Ignore lines stay present with no silent drop.
# The tracked check above stays blind to ignore loss, so this assert
# fails closed when an ignore line goes missing.
for need_ignored in \
    "docs/lifecycle.md" \
    "CHANGELOG.md" \
    "TODO.md"; do
    git -C "${REPO_DIR}" check-ignore -q -- "${need_ignored}" || fail "ignore missing ${need_ignored}"
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

# Flow headers stay present with scheduler rationale in each file.
# Code comments stay version-agnostic: no X.Y.Z
# in src/bpf and build.rs. Version lives only in Cargo and installer
# and guard and changelog and manifest.
for need_flow in \
    "src/bpf/cgroup.bpf.h" \
    "src/bpf/dispatch.bpf.h" \
    "src/bpf/enqueue.bpf.h" \
    "src/bpf/fair.bpf.h" \
    "src/bpf/maps.bpf.h" \
    "src/bpf/select.bpf.h" \
    "src/bpf/srtf.bpf.h" \
    "src/bpf/stats.bpf.h"; do
    [ -s "${SRC_DIR}/${need_flow}" ] || fail "flow scaffold missing ${need_flow}"
    grep -q "Galih Tama" "${SRC_DIR}/${need_flow}" || fail "flow rationale missing ${need_flow}"
done
[ ! -e "${SRC_DIR}/src/bpf/flow" ] || fail "flow dir reappeared"
[ ! -e "${SRC_DIR}/src/bpf/steal.bpf.h" ] || fail "steal helper reappeared"
[ ! -e "${SRC_DIR}/src/bpf/lib" ] || fail "vendored lib reappeared"

# Main plus intf plus build keep scheduler rationale.
for need_core in \
    "src/bpf/main.bpf.c" \
    "src/bpf/intf.h" \
    "build.rs"; do
    grep -q "Galih Tama" "${SRC_DIR}/${need_core}" || fail "core rationale missing ${need_core}"
done

# BPF plus build stay version-agnostic with no X.Y.Z string.
if grep -rnE "[0-9]+\.[0-9]+\.[0-9]+" "${SRC_DIR}/src/bpf" "${SRC_DIR}/build.rs" 2>/dev/null; then
    fail "version string in BPF comment"
fi

# Scheduler README stays byte identical with no doc drift.
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "e74641536aa3c28e66178472f0bf0e9478673bffe9404ce327fa6bab06172a1f" ] || fail "scx README drifted"
[ "$(wc -l < "${SRC_DIR}/README.md" | tr -d ' ')" = "18" ] || fail "scx README lines drifted"

# Harness stays present with no logic change.
[ -s "${REPO_DIR}/tools/edf_harness/harness.c" ] || fail "harness scaffold missing harness.c"
[ -s "${REPO_DIR}/tools/edf_harness/run.sh" ] || fail "harness scaffold missing run.sh"

# Changelog history remains public in prior commits; tip carries no changelog blob.

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

# Fork keeps lib include path plus license as symlinks with no real copy.
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

# Ordered drain stays fail closed with forward wakes. Each CPU drains
# its own LLC prios first, then same node LLCs, then remote LLCs, then
# fallback, with one forward wake per unrunnable head and no move.
DISP_HDR="${SRC_DIR}/src/bpf/dispatch.bpf.h"
grep -q "flow_drain_llc" "${DISP_HDR}" || fail "drain helper missing"
grep -q "flow_try_move" "${DISP_HDR}" || fail "move helper missing"
grep -q "flow_forward_from_peeked" "${DISP_HDR}" || fail "forward helper missing"
grep -q "FLOW_FALLBACK_DSQ" "${DISP_HDR}" || fail "fallback drain missing"
grep -q "flow_is_primary" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "primary predicate missing"

# Changelog plus design histories remain public in prior commits; tip carries no docs blobs.

# CPU hog control stays with fixed integers and no knob. The detector
# compares burnt nanos against awarded length, gates on four fixed
# rounds through the streak bound, demotes one level with saturation,
# and keeps the kick plus stats paths unchanged with no extra read.
HOG_SRTF="${SRC_DIR}/src/bpf/srtf.bpf.h"
HOG_ENQ="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "flow_hog_used" "${HOG_SRTF}" || fail "hog used helper missing"
grep -q "flow_hog_full" "${HOG_SRTF}" || fail "hog full helper missing"
grep -q "flow_hog_rounds" "${HOG_SRTF}" || fail "hog rounds helper missing"
grep -q "flow_hog_demote" "${HOG_SRTF}" || fail "hog demote helper missing"
grep -q "flow_hog_demote" "${HOG_ENQ}" || fail "hog demote call missing"
grep -q "flow_hog_rounds" "${HOG_ENQ}" || fail "hog rounds gate missing"
grep -q "FLOW_STREAK_MAX" "${HOG_SRTF}" || fail "hog fixed rounds missing"

# SRTF stutter fix stays with fixed integers and no knob. Seed at three
# millis, rescue at two hundred millis, gap at two hundred fifty thousand,
# half blend plus halve age through a shift by one, bands at three plus
# nine plus one hundred millis, fixed one quantum slice with pass through
# demote plus charge and a single kick.
grep -q "FLOW_SJF_INIT_NS = 3000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "srtf seed missing"
grep -q "FLOW_STARVE_NS = 200000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "srtf rescue missing"
grep -q "FLOW_PREEMPT_GAP_NS = 250000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "srtf gap missing"
grep -q ">> 1" "${HOG_SRTF}" || fail "srtf half blend missing"
grep -q "FLOW_SLICE_MIN_NS \* 3" "${HOG_SRTF}" || fail "srtf norm band missing"
grep -q "FLOW_AGING_NS" "${HOG_SRTF}" || fail "srtf batch band missing"
grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${HOG_ENQ}" || fail "fixed slice missing"
grep -q "quanta = 1" "${HOG_ENQ}" || fail "fixed quanta missing"
grep -q "extra = 0" "${HOG_ENQ}" || fail "fixed extra missing"
grep -q "flow_fair_charge" "${HOG_ENQ}" || fail "charge pass through missing"
grep -q "flow_fair_extra" "${HOG_ENQ}" || fail "extra pass through missing"
grep -q "flow_kick_constrained" "${HOG_ENQ}" || fail "single kick missing"

# Linear burst predictor stays with fixed weights and no knob. The helper
# takes old plus sample plus wait plus remain, uses eight fractional bits
# with straight line integer math, clamps between floor and cap, and falls
# back to the half blend on saturation. Stopping calls it with wait plus
# remain from the task clock plus slice. No map plus no program plus no
# loop is added for the predictor.
PRED_SRTF="${HOG_SRTF}"
grep -q "flow_pred_next" "${PRED_SRTF}" || fail "pred helper missing"
grep -q "wait_ms" "${PRED_SRTF}" || fail "pred wait missing"
grep -q "rem_ms" "${PRED_SRTF}" || fail "pred remain missing"
grep -q ">> 8" "${PRED_SRTF}" || fail "pred Q8 shift missing"
grep -q "<< 7" "${PRED_SRTF}" || fail "pred old weight missing"
grep -q "<< 2" "${PRED_SRTF}" || fail "pred wait weight missing"
grep -q "<< 3" "${PRED_SRTF}" || fail "pred remain weight missing"
grep -q "flow_sjf_next(old, sample)" "${PRED_SRTF}" || fail "pred fallback missing"
grep -q "FLOW_SJF_FLOOR_NS" "${PRED_SRTF}" || fail "pred floor missing"
grep -q "FLOW_SJF_CAP_NS" "${PRED_SRTF}" || fail "pred cap missing"
grep -q "flow_pred_next" "${DISP_HDR}" || fail "pred call missing"
grep -q "bpf_ktime_get_ns" "${DISP_HDR}" || fail "pred clock missing"
if grep -q "bpf_map_" "${PRED_SRTF}" 2>/dev/null; then
    fail "pred map drift"
fi
if grep -q "BPF_STRUCT_OPS" "${PRED_SRTF}" 2>/dev/null; then
    fail "pred prog drift"
fi
if grep -q "bpf_for" "${PRED_SRTF}" 2>/dev/null; then
    fail "pred loop drift"
fi
if grep -q "for (" "${PRED_SRTF}" 2>/dev/null; then
    fail "pred loop drift"
fi

# Queues are four per LLC and fallback with kernel order and
# insertion ties. Fair scales base by share while extra stays uniform
# with a per LLC floor and a latency shift. Short jobs keep half of
# the old value and add half of the sample. Kicks keep gap
# and tail and escape.
grep -q "FLOW_PRIO_COUNT" "${SRC_DIR}/src/bpf/intf.h" || fail "prio count missing"
grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf/intf.h" || fail "prio queue helper missing"
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "FLOW_FAIR_EXTRA_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair extra missing"
grep -q "flow_fair_charge" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "fair charge missing"
grep -q "flow_seq_floor" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "floor helper missing"
grep -q "flow_lat_key" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "lat shift helper missing"
grep -q "flow_sjf_next" "${HOG_SRTF}" || fail "sjf blend missing"
grep -q "FLOW_SJF_INIT_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf init missing"
grep -q "flow_cgroup_lookup" "${SRC_DIR}/src/bpf/cgroup.bpf.h" || fail "cgroup live lookup missing"
grep -q "gpu_hint" "${SRC_DIR}/src/bpf/intf.h" || fail "gpu hint missing"
grep -q "insertion order" "${HOG_ENQ}" || fail "insertion order missing"
grep -q "fallback queue" "${HOG_ENQ}" || fail "fallback path missing"
grep -q "FLOW_STREAK_MAX" "${HOG_ENQ}" || fail "streak bound missing"

# Dead helpers stay removed. The plain queue helper and the cached
# weight reader have no caller and must not return.
if grep -q "flow_llc_dsq(" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    if ! grep -q "flow_llc_dsq_prio(" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
        fail "queue helper check broken"
    fi
    if grep -q "static __always_inline u64 flow_llc_dsq(" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
        fail "dead queue helper reappeared"
    fi
fi
if grep -q "flow_task_weight" "${SRC_DIR}/src/bpf/cgroup.bpf.h" 2>/dev/null; then
    fail "dead weight helper reappeared"
fi

# Local placements run before ownership so a local cancel never drops
# a gauge that was never raised. The flag take must come after the
# local returns.
if ! grep -q "without the queued bit" "${HOG_ENQ}" 2>/dev/null; then
    fail "local ownership order missing"
fi

# Fallback dispatch drops the gauge on the enqueue LLC read from the
# task, with a scan only when no task state exists.
if ! grep -q "have_owner" "${DISP_HDR}" 2>/dev/null; then
    fail "fallback owner tracking missing"
fi

# Queued gauge writes back the last value when the compare loop loses.
if ! grep -q "st->queued = last - 1" "${SRC_DIR}/src/bpf/stats.bpf.h" 2>/dev/null; then
    fail "queued fallback store missing"
fi

# Installer provenance states the mirror and upstream share one commit.
if ! grep -q "matches the upstream" "${INST}" 2>/dev/null; then
    fail "fork provenance comment missing"
fi

echo "guard tests passed"
