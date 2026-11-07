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
[ "${want}" = "5.2.1" ] || fail "version not at 5.2.1"

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

# Queues come from the upstream library with no vendored copy.
# A missing angled include fails closed here before any build.
[ ! -e "${SRC_DIR}/src/bpf/dhq.bpf.h" ] || fail "own dhq header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/dhq.bpf.c" ] || fail "own dhq source reappeared"
[ ! -e "${SRC_DIR}/src/bpf/topology.bpf.h" ] || fail "own topology header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/topology.bpf.c" ] || fail "own topology source reappeared"
[ ! -e "${SRC_DIR}/src/bpf/lib" ] || fail "vendored lib reappeared"
grep -q '<lib/dhq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled dhq missing"
grep -q '<lib/topology.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled topo missing"

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

# Top README stays concise with layout plus build plus checks and a scheduler ref.
# Scheduler rationale stays signed in BPF headers; top README points at scx/README.md
# with no duplicated lifecycle prose.
for need_note in \
    "## Layout" \
    "## Build" \
    "## Checks"; do
    grep -qF "${need_note}" "${REPO_DIR}/README.md" || fail "readme note missing ${need_note}"
done
grep -qF "scx/README.md" "${REPO_DIR}/README.md" || fail "readme scheduler ref missing"

# Flow headers stay present with scheduler rationale in each file.
# Code comments stay version-agnostic: no X.Y.Z
# in src/bpf and build.rs. Version lives only in Cargo and installer
# and guard and changelog and manifest.
for need_flow in \
    "src/bpf/cgroup.bpf.h" \
    "src/bpf/dispatch.bpf.h" \
    "src/bpf/enqueue.bpf.h" \
    "src/bpf/fair.bpf.h" \
    "src/bpf/lat.bpf.h" \
    "src/bpf/maps.bpf.h" \
    "src/bpf/select.bpf.h" \
    "src/bpf/lst.bpf.h" \
    "src/bpf/stats.bpf.h"; do
    [ -s "${SRC_DIR}/${need_flow}" ] || fail "flow scaffold missing ${need_flow}"
    grep -q "Galih Tama" "${SRC_DIR}/${need_flow}" || fail "flow rationale missing ${need_flow}"
done
[ ! -e "${SRC_DIR}/src/bpf/flow" ] || fail "flow dir reappeared"
[ ! -e "${SRC_DIR}/src/bpf/steal.bpf.h" ] || fail "steal helper reappeared"
[ ! -e "${SRC_DIR}/src/bpf/srtf.bpf.h" ] || fail "srtf header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/sjf.bpf.h" ] || fail "sjf header reappeared"

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
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "c156d2f121d741870a14489083f1e63f5621420054eb028cbd8a9e522f199629" ] || fail "scx README drifted"
[ "$(wc -l < "${SRC_DIR}/README.md" | tr -d ' ')" = "19" ] || fail "scx README lines drifted"

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

# Queues come from upstream with only the license link plus lib link.
grep -q 'upstream library' "${INST}" || fail "lib prose missing"
grep -q '\.\./\.\./\.\./LICENSE' "${INST}" || fail "license symlink missing"
grep -q '\.\./\.\./\.\./\.\./\.\./lib' "${INST}" || fail "lib symlink missing"
grep -q 'rm -rf "${DEST}/src/bpf/lib"' "${INST}" || fail "lib remove missing"

# Kernels below 7.1 are refused with a parsable kernel check.
grep -q '7\.1' "${INST}" || fail "kernel gate missing"
grep -q 'uname -r' "${INST}" || fail "kernel uname guard missing"
grep -q 'compat shims' "${INST}" || fail "kernel compat comment missing"

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
# its own per CPU queues first, then same LLC, then same node, then
# remote, then fallback, with one forward wake per unrunnable head.
DISP_HDR="${SRC_DIR}/src/bpf/dispatch.bpf.h"
grep -q "flow_drain_cpu" "${DISP_HDR}" || fail "drain helper missing"
grep -q "flow_try_move" "${DISP_HDR}" || fail "move helper missing"
grep -q "flow_forward_from_peeked" "${DISP_HDR}" || fail "forward helper missing"
grep -q "FLOW_FALLBACK_DSQ" "${DISP_HDR}" || fail "fallback drain missing"
grep -q "flow_is_primary" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "primary predicate missing"

# Topology keeps local first drain with balanced strands. The drain keeps
# own CPU first then same LLC then same node then remote then fallback,
# strands drain balanced with the larger side first, the pick keeps
# the hint when allowed else the first near target, and ties keep
# the first CPU in fixed order with the previous CPU winning when allowed.
grep -q "drains its own per CPU" "${DISP_HDR}" || fail "cache drain prose missing"
grep -q "larger side first" "${DISP_HDR}" || fail "balanced prose missing"
grep -q "balanced" "${DISP_HDR}" || fail "balanced mode prose missing"
grep -q "flow_constrained_target" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "constrained pick missing"
grep -q "fixed order" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "tie order prose missing"
if ! grep -q "score < best_score" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "tie order drifted"
fi
if grep -q "score <= best_score" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "tie order not fixed"
fi

# Single CPU stands with no sibling probe and fail closed choice.
# No sibling topology probe runs, each CPU stands single, and a miss
# fails closed with no move through the shared picker.
grep -q "No sibling probe" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "smt prose missing"
grep -q "fail closed" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "smt fail closed prose missing"
if grep -q "sibling" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    case "$(grep "sibling" "${SRC_DIR}/src/bpf/select.bpf.h")" in
        *"No sibling probe"*) ;;
        *) fail "smt probe drift" ;;
    esac
fi
if grep -q "smt\|SMT\|sibling_cpu\|topology_sibling" "${SRC_DIR}/src/bpf/dispatch.bpf.h" 2>/dev/null; then
    fail "smt probe reappeared"
fi

# No graphics hint remains. Placement uses the previous CPU plus
# the seed scan only, with no per task hint stored anywhere.
if grep -rqi "gpu" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "gpu hint reappeared"
fi

# Frequency stays governor only with no placement steer. Only a fixed
# hint that never sends zero may reach the governor, and no other
# frequency call steers placement.
grep -q "never steers" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "freq prose missing"
grep -q "never steers" "${DISP_HDR}" || fail "freq dispatch prose missing"
grep -q "never sends zero" "${DISP_HDR}" || fail "freq never zero prose missing"
if grep -q "cpuperf" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
    if ! grep -q "cpuperf_set" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
        fail "freq call not set only"
    fi
fi
if grep -q "scx_bpf_cpufreq\|bpf_cpufreq\|freq_set\|perf_set" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
    fail "freq steer reappeared"
fi

# Changelog plus design histories remain public in prior commits; tip carries no docs blobs.

# LST picks by slack with gap preempts and fixed integers and no knob. Remain
# starts at one slice and burns down to a floor, deadline adds a fixed span
# and is kept until it passes with overdue plus escape counted, slack is
# deadline minus now minus remain with saturation, prio follows slack bands
# with zero plus one slice plus ten slices, and shared enqueues kick for
# preempt on a gap win else idle with a skip otherwise. Stopping plus tick
# burn remain with no blend. No aging plus no starve plus no scale is kept.
LST_HDR="${SRC_DIR}/src/bpf/lst.bpf.h"
LST_ENQ="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "flow_lst_clamp_rem" "${LST_HDR}" || fail "lst clamp missing"
grep -q "flow_lst_slack" "${LST_HDR}" || fail "lst slack missing"
grep -q "flow_lst_prio" "${LST_HDR}" || fail "lst prio missing"
grep -q "FLOW_SLICE_MIN_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice quantum missing"
grep -q "FLOW_LST_REL_NS = 20000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "lst rel missing"
grep -q "FLOW_LST_INIT_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "lst seed missing"
grep -q "FLOW_LST_FLOOR_NS = 5000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "lst floor missing"
grep -q "FLOW_LST_PREEMPT_GAP_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "lst gap missing"
grep -q "FLOW_LST_NORM_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "lst norm missing"
grep -q "FLOW_LST_BATCH_NS = 10000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "lst batch missing"
grep -q "slack <= 0" "${LST_HDR}" || fail "lst lat band missing"
grep -q "FLOW_LST_NORM_NS" "${LST_HDR}" || fail "lst norm use missing"
grep -q "FLOW_LST_BATCH_NS" "${LST_HDR}" || fail "lst batch use missing"
grep -q "return (u32)FLOW_PRIO_LAT" "${LST_HDR}" || fail "lst lat return missing"
grep -q "return (u32)FLOW_PRIO_NORM" "${LST_HDR}" || fail "lst norm return missing"
grep -q "return (u32)FLOW_PRIO_BATCH" "${LST_HDR}" || fail "lst batch return missing"
grep -q "0x7fffffffffffffff" "${LST_HDR}" || fail "saturating bound missing"
if grep -q "FLOW_SJF" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "sjf const reappeared"
fi
if grep -q "flow_sjf_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "sjf helper reappeared"
fi
if grep -q "FLOW_AGING_NS" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "aging const reappeared"
fi
if grep -q "FLOW_STARVE_NS" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "starve const reappeared"
fi
if grep -q "FLOW_HRRN" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "hrrn const reappeared"
fi
if grep -q "mul_sat" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "scale helper reappeared"
fi
if grep -q "FLOW_LAT_OFF_NS\|flow_lat_key\|500001\|1000001\|20000001" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "lat shift reappeared"
fi
if grep -q "float" "${LST_HDR}" 2>/dev/null; then
    fail "float reappeared"
fi
if grep -qi "float" "${SRC_DIR}/src/bpf/enqueue.bpf.h" "${SRC_DIR}/src/bpf/dispatch.bpf.h" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "float reappeared in queue"
fi
if grep -q "ledger\|balancer\|warmth" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "extra table reappeared"
fi
if grep -q "double" "${LST_HDR}" 2>/dev/null; then
    fail "double reappeared"
fi
if grep -q " / " "${LST_HDR}" 2>/dev/null; then
    fail "division reappeared"
fi
if grep -q "/=" "${LST_HDR}" 2>/dev/null; then
    fail "division reappeared"
fi
grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${LST_ENQ}" || fail "fixed slice missing"
grep -q "quanta = 1" "${LST_ENQ}" || fail "fixed quanta missing"
grep -q "extra = 0" "${LST_ENQ}" || fail "fixed extra missing"
grep -q "flow_fair_charge" "${LST_ENQ}" || fail "charge pass through missing"
grep -q "flow_fair_extra" "${LST_ENQ}" || fail "extra pass through missing"
grep -q "flow_kick_idle_only" "${LST_ENQ}" || fail "idle kick missing"
grep -q "flow_kick_lst" "${LST_ENQ}" || fail "gap kick missing"
grep -q "flow_lst_clamp_rem" "${LST_ENQ}" || fail "remain clamp use missing"
grep -q "flow_lst_slack" "${LST_ENQ}" || fail "slack use missing"
grep -q "flow_lst_prio" "${LST_ENQ}" || fail "prio use missing"
grep -q "deadline_ns" "${LST_ENQ}" || fail "deadline use missing"
grep -q "remain_ns" "${LST_ENQ}" || fail "remain use missing"
grep -q "FLOW_LST_PREEMPT_GAP_NS" "${LST_ENQ}" || fail "gap use missing"
grep -q "flow_seq_floor" "${LST_ENQ}" || fail "floor key missing"
grep -q "flow_lst_clamp_rem" "${DISP_HDR}" || fail "remain burn missing"
grep -q "flow_lst_slack" "${DISP_HDR}" || fail "running slack missing"
grep -q "remain_ns" "${DISP_HDR}" || fail "remain field missing"
grep -q "deadline_ns" "${DISP_HDR}" || fail "deadline field missing"
grep -q "slack" "${DISP_HDR}" || fail "slack field missing"
grep -q "reserved" "${SRC_DIR}/src/bpf/intf.h" || fail "reserved field missing"
grep -q "rs->reserved = 0" "${DISP_HDR}" || fail "reserved zero missing"
grep -q "rs->slack" "${DISP_HDR}" || fail "running slack snapshot missing"
grep -q "flow_tick" "${DISP_HDR}" || fail "tick missing"
if grep -q "flow_pred_next" "${LST_HDR}" 2>/dev/null; then
    fail "pred helper reappeared"
fi
if grep -q "flow_pred_next" "${DISP_HDR}" 2>/dev/null; then
    fail "pred call reappeared"
fi
if grep -q "flow_pred_next" "${LST_ENQ}" 2>/dev/null; then
    fail "pred call reappeared"
fi
if grep -q "pred" "${SRC_DIR}/src/bpf/lst.bpf.h" 2>/dev/null; then
    fail "pred text reappeared"
fi
if grep -q "flow_hog_" "${LST_HDR}" 2>/dev/null; then
    fail "hog helper reappeared"
fi
if grep -q "flow_hog_" "${LST_ENQ}" 2>/dev/null; then
    fail "hog call reappeared"
fi
if grep -q "flow_hog_" "${DISP_HDR}" 2>/dev/null; then
    fail "hog call reappeared"
fi
if grep -q "hog_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "hog text reappeared"
fi
if grep -q "FLOW_STREAK_MAX" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "streak bound reappeared"
fi
if grep -q "FLOW_PREEMPT_TAIL_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "tail constant reappeared"
fi
grep -q "SCX_KICK_PREEMPT" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "preempt kick missing"
if grep -q "SCX_KICK_PREEMPT" "${DISP_HDR}" 2>/dev/null; then
    fail "preempt kick drifted to dispatch"
fi
[ "$(grep -rl "SCX_KICK_PREEMPT" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "1" ] || fail "preempt kick not enqueue only"
if grep -q "flow_kick_constrained" "${SRC_DIR}/src/bpf/enqueue.bpf.h" 2>/dev/null; then
    fail "constrained kick reappeared"
fi
if grep -q "flow_kick_pinned" "${SRC_DIR}/src/bpf/enqueue.bpf.h" 2>/dev/null; then
    fail "pinned kick reappeared"
fi
if grep -q "streak" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "streak field reappeared"
fi
if grep -q "streak" "${LST_HDR}" 2>/dev/null; then
    fail "streak helper reappeared"
fi
if grep -q "streak" "${LST_ENQ}" 2>/dev/null; then
    fail "streak use reappeared"
fi
if grep -q "streak" "${DISP_HDR}" 2>/dev/null; then
    fail "streak use reappeared"
fi
grep -q "flow_stat_inc(llc, 6)" "${LST_ENQ}" || fail "preempt count missing"
if grep -q "flow_stat_inc(llc, 6)" "${DISP_HDR}" 2>/dev/null; then
    fail "preempt count drifted to dispatch"
fi
grep -q "flow_stat_inc(llc, 12)" "${LST_ENQ}" || fail "escape count missing"
if grep -q "flow_stat_inc(llc, 12)" "${DISP_HDR}" 2>/dev/null; then
    fail "escape count drifted to dispatch"
fi
grep -q "flow_stat_inc(llc, 17)" "${LST_ENQ}" || fail "lst preempt count missing"
if grep -q "flow_stat_inc(llc, 17)" "${DISP_HDR}" 2>/dev/null; then
    fail "lst preempt drifted to dispatch"
fi
if grep -q "flow_stat_inc(qllc, 17)" "${DISP_HDR}" 2>/dev/null; then
    fail "lst preempt drifted to dispatch"
fi
grep -q "flow_stat_inc(llc, 18)" "${LST_ENQ}" || fail "overdue count missing"
if grep -q "flow_stat_inc(llc, 18)" "${DISP_HDR}" 2>/dev/null; then
    fail "overdue drifted to dispatch"
fi
if grep -q "flow_sjf_" "${LST_HDR}" 2>/dev/null; then
    fail "sjf helper reappeared"
fi
if grep -q "bpf_map_" "${LST_HDR}" 2>/dev/null; then
    fail "lst map drift"
fi
if grep -q "BPF_STRUCT_OPS" "${LST_HDR}" 2>/dev/null; then
    fail "lst prog drift"
fi
if grep -q "bpf_for" "${LST_HDR}" 2>/dev/null; then
    fail "lst loop drift"
fi
if grep -q "for (" "${LST_HDR}" 2>/dev/null; then
    fail "lst loop drift"
fi

# Overdue stays urgent with holds gating gap wins and one kick per run.
# Overdue tasks stay on the first strand with a fresh span, holds gate
# gap wins, idle targets take idle wakes, each run kicks at most once,
# long waiting batch and idle heads drain before normal, running uses
# one clock read, and a runnable yield with no burn still moves time.
grep -q "Overdue tasks stay" "${SRC_DIR}/src/bpf/intf.h" || fail "overdue hold prose missing"
grep -q "Holds gate gap wins" "${SRC_DIR}/src/bpf/intf.h" || fail "hold gate prose missing"
grep -q "Each running instance kicks at most once" "${SRC_DIR}/src/bpf/intf.h" || fail "kick bound prose missing"
grep -q "Long waiting batch" "${SRC_DIR}/src/bpf/intf.h" || fail "wait ceiling prose missing"
grep -q "Pad holds the last kicked" "${SRC_DIR}/src/bpf/intf.h" || fail "kick cookie prose missing"
grep -q "Holds gate gap" "${LST_ENQ}" || fail "enqueue hold gate prose missing"
grep -q "Overdue tasks stay" "${LST_ENQ}" || fail "enqueue overdue prose missing"
grep -q "Each running instance kicks at most once" "${LST_ENQ}" || fail "enqueue kick bound prose missing"
grep -q "flow_wait_hold(tgt, p)" "${LST_ENQ}" || fail "hold gate call missing"
grep -q "scx_bpf_test_and_clear_cpu_idle(tgt)" "${LST_ENQ}" || fail "idle consume missing"
grep -q "rs->pad" "${LST_ENQ}" || fail "kick cookie missing"
grep -q "over = true" "${LST_ENQ}" || fail "overdue flag missing"
grep -q "prio = (u32)FLOW_PRIO_LAT" "${LST_ENQ}" || fail "overdue lat hold missing"
grep -q "flow_wait_long" "${DISP_HDR}" || fail "wait ceiling helper missing"
grep -q "flow_head_long" "${DISP_HDR}" || fail "head wait helper missing"
grep -q "Long waiting batch" "${DISP_HDR}" || fail "drain ceiling prose missing"
grep -q "flow_lat_observe(cpu, t, now, 1)" "${DISP_HDR}" || fail "single clock observe missing"
grep -q "flow_fair_cap_add(t->vtime, 1)" "${DISP_HDR}" || fail "yield advance missing"

# Stats keep order with laxity names at the same offsets.
# Twenty one counters stay in struct order at 168 bytes with total
# matching penalty and extra combined per award.
grep -q "kick_preempt" "${SRC_DIR}/src/bpf/intf.h" || fail "preempt field missing"
grep -q "lst_escape" "${SRC_DIR}/src/bpf/intf.h" || fail "escape field missing"
grep -q "lst_urgent" "${SRC_DIR}/src/bpf/intf.h" || fail "urgent field missing"
grep -q "lst_hold" "${SRC_DIR}/src/bpf/intf.h" || fail "hold field missing"
grep -q "lst_preempt" "${SRC_DIR}/src/bpf/intf.h" || fail "lst win field missing"
grep -q "lst_overdue" "${SRC_DIR}/src/bpf/intf.h" || fail "overdue field missing"
grep -q "kick_preempt" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "lst_escape" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "lst_urgent" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "lst_hold" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "lst_preempt" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "lst_overdue" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "kick_preempt" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "lst_escape" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "lst_urgent" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "lst_hold" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "lst_preempt" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "lst_overdue" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
if grep -q "hog_escape\|hog_hold\|lat_boost\|lat_preempt\|age_rescue" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "old stats name reappeared"
fi
if grep -q "hog_escape\|hog_hold\|lat_boost\|lat_preempt\|age_rescue" "${SRC_DIR}/src/stats.rs" 2>/dev/null; then
    fail "old stats name reappeared"
fi
if grep -q "hog_escape\|hog_hold\|lat_boost\|lat_preempt\|age_rescue" "${SRC_DIR}/src/metrics.rs" 2>/dev/null; then
    fail "old stats name reappeared"
fi

# Wait hist stays scoped with five maps and nine headers.
# The wait map is one array past the base tables with per CPU
# run plus dispatch halves. Top keeps twenty one counters. Queues
# come from upstream, so quoted headers drop by two while maps stay.
[ "$(grep -rh 'SEC(".maps")' "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "5" ] || fail "maps count drifted"
[ "$(grep -c 'include ".*\.bpf\.h"' "${SRC_DIR}/src/bpf/main.bpf.c" | tr -d ' ')" = "9" ] || fail "headers count drifted"
grep -q 'include "lat.bpf.h"' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "lat include missing"
grep -q '<lib/dhq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled dhq missing"
grep -q '<lib/topology.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled topo missing"
grep -q 'add_source.*lib/arena.bpf.c' "${SRC_DIR}/build.rs" || fail "arena source missing"
grep -q 'add_source.*lib/dhq.bpf.c' "${SRC_DIR}/build.rs" || fail "dhq lib missing"
grep -q 'add_source.*lib/topology.bpf.c' "${SRC_DIR}/build.rs" || fail "topo lib missing"
grep -q 'add_source.*lib/minheap.bpf.c' "${SRC_DIR}/build.rs" || fail "minheap lib missing"
grep -q 'add_source.*lib/sdt_task.bpf.c' "${SRC_DIR}/build.rs" || fail "task lib missing"
grep -q 'compile_link_gen' "${SRC_DIR}/build.rs" || fail "link helper missing"
grep -q "lat_hist" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "wait map missing"
grep -q "BPF_MAP_TYPE_ARRAY" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "wait map type missing"
grep -q "FLOW_LAT_KINDS = 9" "${SRC_DIR}/src/bpf/intf.h" || fail "wait kinds missing"
grep -q "FLOW_LAT_BUCKETS = 8" "${SRC_DIR}/src/bpf/intf.h" || fail "wait buckets missing"
grep -q "FLOW_HIST_LEN = 144" "${SRC_DIR}/src/bpf/intf.h" || fail "wait hist len missing"
grep -q "lat_kind" "${SRC_DIR}/src/bpf/intf.h" || fail "wait task tail missing"
grep -q "flow_lat_hist" "${SRC_DIR}/src/bpf/intf.h" || fail "wait hist struct missing"
grep -q "flow_lat_bucket" "${SRC_DIR}/src/bpf/lat.bpf.h" || fail "wait bucket missing"
grep -q "flow_lat_record" "${SRC_DIR}/src/bpf/lat.bpf.h" || fail "wait record missing"
grep -q "flow_lat_store" "${SRC_DIR}/src/bpf/lat.bpf.h" || fail "wait store missing"
grep -q "flow_lat_finalize" "${SRC_DIR}/src/bpf/lat.bpf.h" || fail "wait finalize missing"
grep -q "flow_lat_observe" "${SRC_DIR}/src/bpf/lat.bpf.h" || fail "wait observe missing"
grep -q "flow_lat_store" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "select store missing"
grep -q "flow_lat_finalize" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "enqueue finalize missing"
grep -q "flow_lat_observe" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "dispatch observe missing"
grep -q "LatMetrics" "${SRC_DIR}/src/stats.rs" || fail "lat stats missing"
grep -q '"lat"' "${SRC_DIR}/src/stats.rs" || fail "lat endpoint missing"
grep -q "LatMetrics" "${SRC_DIR}/src/metrics.rs" || fail "lat fold missing"
grep -q "FLOW_HIST_LEN" "${SRC_DIR}/src/metrics.rs" || fail "hist len use missing"
grep -q "fold_lat_val" "${SRC_DIR}/src/metrics.rs" || fail "lat fold helper missing"
grep -q "collect_lat" "${SRC_DIR}/src/metrics.rs" || fail "lat collect missing"
grep -q "LatMetrics" "${SRC_DIR}/src/run.rs" || fail "run lat missing"
grep -q "LatMetrics" "${SRC_DIR}/src/main.rs" || fail "help stats lat missing"
if grep -q "for (" "${SRC_DIR}/src/bpf/lat.bpf.h" 2>/dev/null; then
    fail "wait loop drift"
fi
if grep -q "bpf_for" "${SRC_DIR}/src/bpf/lat.bpf.h" 2>/dev/null; then
    fail "wait loop drift"
fi
if grep -q "bpf_map_" "${SRC_DIR}/src/bpf/lat.bpf.h" 2>/dev/null; then
    case "$(grep "bpf_map_" "${SRC_DIR}/src/bpf/lat.bpf.h")" in
        *bpf_map_lookup_elem*) ;;
        *) fail "wait map drift" ;;
    esac
fi

# Ops stay at sixteen with no probe added.
[ "$(grep -rh "BPF_STRUCT_OPS" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "16" ] || fail "ops count drifted"

# Queues are one per CPU plus fallback with upstream order and
# insertion ties. Fair scales base by share while extra stays uniform
# with a per LLC floor. Laxity sets the strand by slack bands with a
# gap preempt on shared tasks. Wakes go preempt on a gap win else
# idle with a skip otherwise. Strands stay balanced with an imbalance
# cap so no strand starves. Queues use the upstream library with per
# CPU placement and FIFO fallback.
grep -q "FLOW_PRIO_COUNT" "${SRC_DIR}/src/bpf/intf.h" || fail "prio count missing"
grep -q "FLOW_FALLBACK_CAP = 1024ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "fallback cap missing"
grep -q "SCX_DHQ_STRAND_A" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "strand use missing"
grep -q "SCX_DHQ_STRAND_B" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "strand use missing"
grep -q "SCX_DHQ_MODE_BALANCED" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "mode use missing"
grep -q "scx_dhq_create_balanced" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "queue create missing"
grep -q "256ULL" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "percpu cap missing"
grep -q "8ULL" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "imbalance cap missing"
grep -q "scx_dhq_insert_vtime" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "queue insert missing"
grep -q "scx_dhq_pop_strand" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "queue pop missing"
grep -q "scx_dhq_peek_strand" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "queue peek missing"
grep -q "scx_dhq_nr_queued_strand" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "queue count missing"
grep -q "flow_dhqs" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "queue handle missing"
grep -q "topo_all" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo tree missing"
grep -q "TOPO_FOR_EACH_NODE" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo walk missing"
grep -q "topo_contains" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo test missing"
grep -q "topo_cpu_to_llc_id" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "topo llc missing"
grep -q "topo_all" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "dispatch topo missing"
if grep -q "flow_dhq_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "own queue helper reappeared"
fi
if grep -q "flow_topo_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "own topo helper reappeared"
fi
if grep -q "FLOW_DHQ_BASE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "queue base reappeared"
fi
if grep -q "FLOW_DHQ_STRAND" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "queue const reappeared"
fi
if grep -q "FLOW_DHQ_MODE" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "mode const reappeared"
fi
if grep -q "FLOW_DHQ_PERCPU" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "percpu const reappeared"
fi
if grep -q "FLOW_DHQ_MAX" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "imbalance const reappeared"
fi
if grep -q "flow_dhq_id" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "queue id reappeared"
fi
if grep -q "flow_dhq_live" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "queue live reappeared"
fi
if grep -q "flow_llc_node" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "node cache reappeared"
fi
if grep -q "flow_nr_cpus\|flow_nr_llcs" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "count cache reappeared"
fi
if grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "priq helper reappeared"
fi
if grep -q "FLOW_LLC_BASE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "llc base reappeared"
fi
if grep -q "FLOW_PRIO_COUNT" "${SRC_DIR}/src/bpf/dispatch.bpf.h" 2>/dev/null; then
    fail "prio queue reappeared"
fi
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "FLOW_FAIR_EXTRA_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair extra missing"
grep -q "flow_fair_charge" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "fair charge missing"
grep -q "flow_seq_floor" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "floor helper missing"
if grep -q "flow_lat_key" "${SRC_DIR}/src/bpf/fair.bpf.h" 2>/dev/null; then
    fail "lat shift helper reappeared"
fi
grep -q "flow_lst_clamp_rem" "${LST_HDR}" || fail "lst clamp missing"
grep -q "FLOW_LST_INIT_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "lst init missing"
grep -q "flow_cgroup_lookup" "${SRC_DIR}/src/bpf/cgroup.bpf.h" || fail "cgroup live lookup missing"
grep -q "insertion order" "${LST_ENQ}" || fail "insertion order missing"
grep -q "fallback queue" "${LST_ENQ}" || fail "fallback path missing"
grep -q "kick_idle" "${SRC_DIR}/src/bpf/intf.h" || fail "idle count missing"
grep -q "kick_skip" "${SRC_DIR}/src/bpf/intf.h" || fail "skip count missing"
grep -q 'include "lst.bpf.h"' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "lst include missing"
if grep -q 'include "sjf.bpf.h"' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "sjf include reappeared"
fi

# Dead helpers stay removed. The per LLC prio queue helper and the cached
# weight reader have no caller and must not return.
if grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead queue helper reappeared"
fi
if grep -q "flow_task_weight" "${SRC_DIR}/src/bpf/cgroup.bpf.h" 2>/dev/null; then
    fail "dead weight helper reappeared"
fi

# Local placements run before ownership so a local cancel never drops
# a gauge that was never raised. The flag take must come after the
# local returns.
if ! grep -q "without the queued bit" "${LST_ENQ}" 2>/dev/null; then
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

# Fallback stays FIFO only with no vtime insert naming the fallback queue.
if grep -q "insert_vtime.*FALLBACK\|FALLBACK.*insert_vtime" "${SRC_DIR}/src/bpf/enqueue.bpf.h" 2>/dev/null; then
    fail "fallback vtime insert reappeared"
fi
grep -q "scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "fallback fifo insert missing"

# Peek goes through the compat helper with no raw call left.
grep -q "__COMPAT_scx_bpf_dsq_peek" "${DISP_HDR}" || fail "compat peek missing"
if grep -q "[^_]scx_bpf_dsq_peek(" "${DISP_HDR}" 2>/dev/null; then
    fail "raw peek reappeared"
fi

# Dispatch reads the node from the tree with no per-CPU walk.
if grep -q "tcc->llc_id\|t2->llc_id" "${DISP_HDR}" 2>/dev/null; then
    fail "dead cpu scan reappeared"
fi
grep -q "topo_contains" "${DISP_HDR}" || fail "tree order missing"
# Drain peeks every queue with no gauge skip.
if grep -q "flow_stats_for(victim)" "${DISP_HDR}" 2>/dev/null; then
    fail "gauge bail reappeared"
fi

# Select rechecks the winning pick against the current mask.
grep -q "flow_cpu_allowed(best, p)" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "pick clamp missing"

# Task init resolves the cgroup through compat and clears vtime through compat.
grep -q "scx_bpf_task_cgroup(p)" "${DISP_HDR}" || fail "task cgroup compat missing"
grep -q "scx_bpf_task_set_dsq_vtime" "${DISP_HDR}" || fail "dsq vtime setter missing"
grep -q "scx_bpf_now()" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "compat clock missing"

# Fresh storage repairs home to unset so running records the first CPU.
# A zero remain with a zero home marks a fresh entry that would stick to CPU0.
grep -q "home_cpu = -1" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "home repair missing"
grep -q "remain_ns.*home_cpu" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "home repair guard missing"

# Thread shape defaults on so a missed seed stays conservative.
# Userspace seeds the data section before load with the kernel default on miss.
grep -q "flow_smt_enabled = 1" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "smt default missing"
grep -q "data_data" "${SRC_DIR}/src/run.rs" || fail "smt seed drifted"
grep -q "flow_smt_enabled" "${SRC_DIR}/src/run.rs" || fail "smt seed drifted"
if grep -q "bss_data.*flow_smt_enabled" "${SRC_DIR}/src/run.rs" 2>/dev/null; then
    fail "smt seed section drifted"
fi

# Distant holds decay after one long so a single old long never blocks holds.
# Holds count a skip with the same cluster excluded and longs bounding.
grep -q "fetch_and_and.*cells" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "hold decay missing"
grep -q "suppress one hold then decay" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "hold decay prose missing"

# Cluster width stays heuristic with the tie favor kept on shared threads.
# Width four splits larger clusters without ever merging distant cores,
# and only the fast pick is gated on single threads.
grep -q "Width four is a heuristic" "${SRC_DIR}/src/topology.rs" || fail "cluster heuristic missing"
grep -q "tie favor kept" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "tie favor prose missing"

echo "guard tests passed"
