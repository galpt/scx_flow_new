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
[ "${want}" = "5.2.26" ] || fail "version not at 5.2.26"

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
[ ! -e "${SRC_DIR}/src/bpf/edq.bpf.h" ] || fail "own edq header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/edq.bpf.c" ] || fail "own edq source reappeared"
[ ! -e "${SRC_DIR}/src/bpf/topology.bpf.h" ] || fail "own topology header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/topology.bpf.c" ] || fail "own topology source reappeared"
[ -L "${SRC_DIR}/src/bpf/lib" ] || fail "lib link missing"
[ "$(readlink "${SRC_DIR}/src/bpf/lib")" = "../../../../../lib" ] || fail "lib link drifted"
[ -L "${SRC_DIR}/lib" ] || fail "top lib link missing"
[ "$(readlink "${SRC_DIR}/lib")" = "../../../../../lib" ] || fail "top lib link drifted"
# Both lib links stay tracked for direct cloners with no installer needed.
# A standalone clone shows both links with the upstream blob.
git -C "${REPO_DIR}" ls-files -s -- scx/lib | grep -q "120000 c2c14b99593a77b7cfd27314aff6d458fef70dd7" || fail "top lib not tracked"
git -C "${REPO_DIR}" ls-files -s -- scx/src/bpf/lib | grep -q "120000 c2c14b99593a77b7cfd27314aff6d458fef70dd7" || fail "lib not tracked"
if grep -q '<lib/rbtree.h>' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "rbtree angled reappeared for honest BST"
fi
if grep -q '<lib/edq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" 2>/dev/null; then
    fail "angled edq reappeared"
fi
if grep -q '<lib/dhq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" 2>/dev/null; then
    fail "angled dhq reappeared"
fi
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
    "src/bpf/dispatch.bpf.h" \
    "src/bpf/enqueue.bpf.h" \
    "src/bpf/fair.bpf.h" \
    "src/bpf/maps.bpf.h" \
    "src/bpf/select.bpf.h" \
    "src/bpf/stats.bpf.h"; do
    [ -s "${SRC_DIR}/${need_flow}" ] || fail "flow scaffold missing ${need_flow}"
    grep -q "Galih Tama" "${SRC_DIR}/${need_flow}" || fail "flow rationale missing ${need_flow}"
done
[ ! -e "${SRC_DIR}/src/bpf/cgroup.bpf.h" ] || fail "cgroup header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/flow" ] || fail "flow dir reappeared"
[ ! -e "${SRC_DIR}/src/bpf/steal.bpf.h" ] || fail "steal helper reappeared"
[ ! -e "${SRC_DIR}/src/bpf/srtf.bpf.h" ] || fail "srtf header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/sjf.bpf.h" ] || fail "sjf header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/edf.bpf.h" ] || fail "edf header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/lat.bpf.h" ] || fail "lat header reappeared"
[ ! -e "${SRC_DIR}/src/bpf/lst.bpf.h" ] || fail "dead header reappeared"

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
# Per-LLC virtual deadline DSQ plus per-CPU DSQ plus fallback FIFO DSQ.
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "765115210c5c61a7275771dd8b7f2c6d15357e9b32798476eb56f3949f4ef902" ] || fail "scx README drifted"
[ "$(wc -l < "${SRC_DIR}/README.md" | tr -d ' ')" = "15" ] || fail "scx README lines drifted"
[ "$(wc -w < "${SRC_DIR}/README.md" | tr -d ' ')" = "158" ] || fail "scx README words drifted"

# Scheduler prose keeps periods with no semicolon.
if grep -q ";" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "scx README semicolon reappeared"
fi

# Harness stays present with report fields and no workload change.
[ -s "${REPO_DIR}/tools/edf_harness/harness.c" ] || fail "harness scaffold missing harness.c"
[ -s "${REPO_DIR}/tools/edf_harness/run.sh" ] || fail "harness scaffold missing run.sh"
grep -q "probe_p99_us" "${REPO_DIR}/tools/edf_harness/harness.c" || fail "harness p99 missing"
grep -q "spill" "${REPO_DIR}/tools/edf_harness/harness.c" || fail "harness spill missing"
grep -q "occupancy" "${REPO_DIR}/tools/edf_harness/harness.c" || fail "harness occupancy missing"
grep -q "probe_p99_us" "${REPO_DIR}/tools/edf_harness/run.sh" || fail "harness report missing p99"

# Hint tooling stays removed with no reappearance.
# The offline probe left the tree, so its dir plus its tracked
# files plus its scoped names must not return. Scoped names stay
# narrow so topology hint locals plus share prose keep passing.
[ ! -e "${REPO_DIR}/tools/nn_hint" ] || fail "hint dir reappeared"
if git -C "${REPO_DIR}" ls-files -- tools/nn_hint | grep -q .; then
    fail "hint files reappeared"
fi
for hint_name in \
    "nn_hint" \
    "hint_for" \
    "taxonomy_for" \
    "share_for" \
    "load_lestat" \
    "burst <= 66" \
    "calibration still required"; do
    if grep -rn --exclude="test_install_guard.sh" --exclude-dir=target --exclude-dir=.git "${hint_name}" "${REPO_DIR}" 2>/dev/null | grep -q .; then
        fail "hint name reappeared ${hint_name}"
    fi
done

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

# Queues come from upstream with only the license link plus lib links.
grep -q 'upstream library' "${INST}" || fail "lib prose missing"
grep -q '\.\./\.\./\.\./LICENSE' "${INST}" || fail "license symlink missing"
grep -q '\.\./\.\./\.\./\.\./\.\./lib' "${INST}" || fail "lib symlink missing"
grep -q 'rm -rf -- "${DEST}/src/bpf/lib"' "${INST}" || fail "lib remove missing"
grep -q 'rm -rf -- "${DEST}/lib"' "${INST}" || fail "top lib remove missing"
grep -q 'readlink "${DEST}/lib"' "${INST}" || fail "top lib guard missing"
grep -q 'ln -s ../../../../../lib "${DEST}/lib"' "${INST}" || fail "top lib symlink missing"
grep -q 'ln -s ../../../../../lib "${DEST}/src/bpf/lib"' "${INST}" || fail "lib symlink missing"
grep -q 'rsync -a' "${INST}" || fail "rsync archive missing"
if grep -q -- '--copy-links' "${INST}" 2>/dev/null; then
    fail "copy links reappeared"
fi
if grep -q -- '--dereference' "${INST}" 2>/dev/null; then
    fail "dereference reappeared"
fi
if grep -q '"${DEST}/src/bpf/lib/"' "${INST}" 2>/dev/null; then
    fail "trailing slash reappeared"
fi

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
grep -q 'rm -f --' "${INST}" || fail "rm file dash missing"
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

# Ordered DSQ drain stays fail closed. Each CPU drains its own CPU DSQ
# first for pinned tasks, then the local LLC DSQ for shared tasks, then
# same node neighbor LLC DSQs, then remote LLC DSQs, then fallback last.
# Continuation keeps a runnable prev in place with a fresh slice.
DISP_HDR="${SRC_DIR}/src/bpf/dispatch.bpf.h"
grep -q "FLOW_CPU_DSQ_BASE = 0x1000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "cpu dsq base missing"
grep -q "FLOW_LLC_DSQ_BASE = 0x2000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "llc dsq base missing"
grep -q "FLOW_FALLBACK_DSQ = 0x6100ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "fallback dsq base missing"
grep -q "FLOW_CPU_DSQ_BASE" "${DISP_HDR}" || fail "cpu drain missing"
grep -q "FLOW_LLC_DSQ_BASE" "${DISP_HDR}" || fail "llc drain missing"
grep -q "FLOW_FALLBACK_DSQ" "${DISP_HDR}" || fail "fallback drain missing"
grep -q "flow_try_continue_prev" "${DISP_HDR}" || fail "continue helper missing"
grep -q "Same node neighbor" "${DISP_HDR}" || fail "node drain missing"
grep -q "Remote LLC" "${DISP_HDR}" || fail "remote drain missing"
grep -q "Fallback last" "${DISP_HDR}" || fail "fallback order missing"
if grep -q "flow_drain_cpu\|flow_try_move\|flow_forward_from_peeked" "${DISP_HDR}" 2>/dev/null; then
    fail "stale drain helper reappeared"
fi
if grep -q "flow_is_primary" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "dead primary reappeared"
fi

# Topology keeps local first DSQ drain in due time order. The drain keeps
# own CPU DSQ first then local LLC DSQ then same node then remote then
# fallback last, the pick keeps the hint when allowed else the first
# allowed CPU, and ties keep fixed order.
grep -q "Own CPU DSQ" "${DISP_HDR}" || fail "cache drain prose missing"
grep -q "Local LLC DSQ" "${DISP_HDR}" || fail "llc drain prose missing"
grep -q "due time" "${DISP_HDR}" || fail "due order prose missing"
if grep -q "first strand" "${DISP_HDR}" 2>/dev/null; then
    fail "strand prose reappeared"
fi
grep -q "flow_constrained_target" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "constrained pick missing"
grep -q "fixed order" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "tie order prose missing"
if grep -q "score < best_score\|score <= best_score" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "stale score tie reappeared"
fi

# Burst-aware SMT placement with fail closed choice.
# Fully idle cores win first, micro-bursts stay cache-warm, and a miss
# fails closed with no move through the shared picker.
grep -q "scx_bpf_get_idle_smtmask" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "smt mask missing"
grep -q "scx_bpf_get_idle_cpumask" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "idle mask missing"
grep -q "FLOW_FLAG_IS_SYNC_WAKEUP" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "sync flag missing"
grep -q "FLOW_FLAG_WOKEN_BY_HARDIRQ" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "hardirq flag missing"
grep -q "FLOW_FLAG_WOKEN_BY_SOFTIRQ" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "softirq flag missing"
grep -q "FLOW_FLAG_IS_GREEDY" "${SRC_DIR}/src/bpf/intf.h" || fail "greedy flag missing"
if grep -q "FLOW_SMT_STAY_BURST_NS\|short_burst\|full_core" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "stale smt burst reappeared"
fi
if grep -q "FLOW_FLAG_URGENT\|FLOW_FLAG_INTERACTIVE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale urgent reappeared"
fi
if grep -q "sibling_cpu\|topology_sibling" "${SRC_DIR}/src/bpf/dispatch.bpf.h" 2>/dev/null; then
    fail "smt probe reappeared"
fi

# Latency score plus in-place continuation plus direct dispatch.
# Continuation keeps a runnable prev on its CPU with a fresh slice.
grep -q "flow_try_continue_prev" "${SRC_DIR}/src/bpf/dispatch.bpf.h" || fail "try continue missing"
grep -q "SCX_DSQ_LOCAL" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "local dispatch missing"
grep -q "SCX_DSQ_LOCAL_ON" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "local on missing"
grep -q "scx_bpf_test_and_clear_cpu_idle(tgt)" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "idle claim missing"
grep -q "FLOW_FLAG_IS_GREEDY" "${SRC_DIR}/src/bpf/intf.h" || fail "greedy flag missing"
grep -q "FLOW_SLICE_MAX_NS = 5000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice max missing"
grep -q "FLOW_SLICE_MIN_NS = 500000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice min missing"
grep -q "FLOW_TARGETED_LATENCY_NS = 10000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "target latency missing"
if grep -q "flow_cpu_min_key" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale min key reappeared"
fi
if grep -q "FLOW_CADENCE_MAX_NS\|FLOW_FLAG_URGENT\|FLOW_FLAG_INTERACTIVE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale cadence reappeared"
fi

# No graphics hint remains. Placement uses the previous CPU plus
# the seed scan only, with no per task hint stored anywhere.
if grep -rqi "gpu" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "gpu hint reappeared"
fi

# Busy cores run at max with idle cores at half through one set call.
# The call never sends zero and never steers placement, and no other
# frequency call steers placement. Timer only decays idle cores while
# running plus tick ramp busy cores to max. Shared mark lives in select
# so the set plus max plus half checks read select with use checks in dispatch.
grep -q "never steers" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "freq prose missing"
grep -q "never touches a busy core" "${DISP_HDR}" || fail "freq dispatch prose missing"
grep -q "never sends zero" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "freq never zero prose missing"
grep -q "scx_bpf_cpuperf_set" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "cpuperf set missing"
grep -q "SCX_CPUPERF_ONE" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "cpuperf max missing"
grep -q "SCX_CPUPERF_ONE / 2" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "cpuperf half missing"
grep -q "flow_cpuperf_mark" "${DISP_HDR}" || fail "cpuperf use missing"
if grep -q "cpuperf" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
    if ! grep -q "cpuperf_set" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
        fail "freq call not set only"
    fi
fi
if grep "scx_bpf_cpufreq\|bpf_cpufreq\|freq_set\|perf_set" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null | grep -v "scx_bpf_cpuperf_set" | grep -q .; then
    fail "freq steer reappeared"
fi

# Changelog plus design histories remain public in prior commits; tip carries no docs blobs.

# Pure deadline ordering with fixed integers and no knob. Deadline adds
# the burst scaled nice step to the floored time, queue key is deadline
# with FIFO fallback, and shared enqueues kick for preempt on
# an earlier deadline else idle with a skip otherwise. Stopping plus tick charge
# burnt time with burst as the only extra state. No float plus no new divide
# is kept.
FAIR_HDR="${SRC_DIR}/src/bpf/fair.bpf.h"
ENQ_HDR="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "FLOW_SLICE_MIN_NS = 500000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice quantum missing"
if grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "stale fair base reappeared"
fi
grep -q "flow_calc_lat_cri" "${FAIR_HDR}" || fail "lat cri missing"
grep -q "flow_calc_greedy_penalty" "${FAIR_HDR}" || fail "greedy missing"
grep -q "flow_calc_when_to_run" "${FAIR_HDR}" || fail "when run missing"
grep -q "flow_nice_table" "${FAIR_HDR}" || fail "nice table missing"
grep -q "flow_nice_weight" "${FAIR_HDR}" || fail "nice weight missing"
if grep -rq "flow_combine" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "combine reappeared"
fi
grep -q "flow_task_weight" "${FAIR_HDR}" || fail "task weight missing"
grep -q "flow_calc_lat_cri(p, t)" "${ENQ_HDR}" || fail "lat cri enqueue missing"
grep -q "flow_task_weight(p, t)" "${DISP_HDR}" || fail "task weight dispatch missing"
grep -q "flow_calc_avg" "${FAIR_HDR}" || fail "avg helper missing"
if grep -q "flow_nice_weight(p)" "${ENQ_HDR}" 2>/dev/null; then
    fail "nice direct reappeared"
fi
# Latency score keeps integer only math with log scale plus EWMA folds.
# Due time lands ahead of the clock inside a small window for urgent tasks.
# Slice tracks a ten millisecond window with boost for long frame runs.
grep -q "flow_log2_u64" "${FAIR_HDR}" || fail "log helper missing"
grep -q "flow_calc_avg" "${FAIR_HDR}" || fail "avg helper missing"
grep -q "flow_calc_lat_cri" "${FAIR_HDR}" || fail "lat cri missing"
grep -q "flow_calc_greedy_penalty" "${FAIR_HDR}" || fail "greedy missing"
grep -q "flow_calc_when_to_run" "${FAIR_HDR}" || fail "when run missing"
grep -q "flow_calc_slice" "${FAIR_HDR}" || fail "calc slice missing"
grep -q "flow_calc_slice(t," "${ENQ_HDR}" || fail "calc slice use missing"
grep -q "flow_calc_slice(t," "${DISP_HDR}" || fail "calc slice dispatch missing"
grep -q "flow_calc_when_to_run(p, t)" "${ENQ_HDR}" || fail "when run use missing"
if grep -q "flow_seq_floor\|flow_vd_for\|flow_eevdf_vd\|flow_burst_\|flow_fair_step\|flow_fair_cap_add\|flow_fair_charge\|flow_vd_wakeup_assist" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale fair reappeared"
fi
if grep -q "FLOW_SLICE_FLOOR_NS\|FLOW_SEQ_FLOOR_STEP_NS\|FLOW_FAIR_BASE_NS\|FLOW_CGROUP_WEIGHT_MIN.*burst" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale burst const reappeared"
fi
if grep -q "vd_HRRN\|hrrn_ready\|flow_run_vd\|flow_run_slice" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "hrrn reappeared"
fi
if grep -q "flow_rb_empty\|flow_rb_insert\|flow_rb_for_cpu" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale rb reappeared"
fi
grep -q "SCX_ENQ_WAKEUP" "${ENQ_HDR}" || fail "wakeup check missing"
# No overload control with unbounded admit plus FIFO fallback and no reclaim.
# DSQ inserts stay direct with pinned on per-CPU plus shared on per-LLC
# plus fallback FIFO for tasks with no usable CPU. No room probe remains.
if grep -q "scx_edq_\|flow_rb_insert\|flow_enqueue_insert_shared\|flow_try_evict" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale queue helper reappeared"
fi
grep -q "FLOW_CPU_DSQ_BASE" "${ENQ_HDR}" || fail "cpu dsq insert missing"
grep -q "FLOW_LLC_DSQ_BASE" "${ENQ_HDR}" || fail "llc dsq insert missing"
grep -q "FLOW_FALLBACK_DSQ" "${ENQ_HDR}" || fail "fallback insert missing"
if grep -q "scx_edq_nr_queued\|nr < (u64)FLOW_QUEUE_CAP" "${ENQ_HDR}" 2>/dev/null; then
    fail "room gate reappeared"
fi
if grep -q "FLOW_RED_TOL_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "red tol reappeared"
fi
if grep -q "FLOW_RED_EMAX_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "red emax reappeared"
fi
if grep -q "FLOW_RED_EVICT_MAX" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "red evict bound reappeared"
fi
if grep -q "flow_red_cost" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "red cost reappeared"
fi
if grep -q "flow_red_exceed" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "red exceed reappeared"
fi
if grep -q "flow_red_gate" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "red gate reappeared"
fi
if grep -q "flow_band_for_weight" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "band helper reappeared"
fi
if grep -q "128U << 3" "${FAIR_HDR}" 2>/dev/null; then
    fail "band shift reappeared"
fi
if grep -q "128U >> 3" "${FAIR_HDR}" 2>/dev/null; then
    fail "band shift reappeared"
fi
if grep -q "flow_try_evict_one" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "evict helper reappeared"
fi
if grep -q "flow_reclaim_kick" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "reclaim helper reappeared"
fi
if grep -q "flow_red_gate(cost, exceed, nr)" "${ENQ_HDR}" 2>/dev/null; then
    fail "gate use reappeared"
fi
if grep -q "flow_band_for_weight(w)" "${ENQ_HDR}" 2>/dev/null; then
    fail "band use reappeared"
fi
if grep -q "flow_reclaim_kick(saved" "${DISP_HDR}" 2>/dev/null; then
    fail "reclaim use reappeared"
fi
if grep -q "scx_edq_try_peek_nth_hold" "${ENQ_HDR}" 2>/dev/null; then
    fail "bounded evict scan reappeared"
fi
if grep -q "scx_edq_try_remove" "${ENQ_HDR}" 2>/dev/null; then
    fail "evict remove reappeared"
fi
if grep -q "tolerance plus bound plus room plus cap" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "overload prose reappeared"
fi
if grep -q "lowest band" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "band prose reappeared"
fi
if grep -q "lowest implicit band" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "band prose reappeared"
fi
if grep -q "saved delta" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "reclaim prose reappeared"
fi
# DSQ inserts need no evict plus no reclaim. Pinned tasks park on the
# per-CPU DSQ while shared tasks park on the per-LLC DSQ with FIFO fallback.
grep -q "FLOW_CPU_DSQ_BASE" "${ENQ_HDR}" || fail "cpu insert missing"
grep -q "FLOW_LLC_DSQ_BASE" "${ENQ_HDR}" || fail "llc insert missing"
grep -q "FLOW_FALLBACK_DSQ" "${ENQ_HDR}" || fail "fallback insert missing"
# Tick plus stopping charge the tail past the last tick and fold averages.
grep -q "acc_runtime_ns" "${DISP_HDR}" || fail "tail charge missing"
grep -q "avg_runtime_ns" "${DISP_HDR}" || fail "avg fold missing"
# Effective weight from nice plus live share with clamp combine and no map.
# Live share reads as the default with clamp to one through ten thousand.
# Hierarchy walk stays out of budget, so misses keep nice only. Steady
# tasks price the kept max through the shared charge path.
if grep -rq "cgrp_weight_stor" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "group map reappeared"
fi
if grep -rn "cgrp_id" "${SRC_DIR}/src/bpf" "${SRC_DIR}/src/run.rs" "${SRC_DIR}/src/stats.rs" "${SRC_DIR}/src/metrics.rs" "${SRC_DIR}/src/topology.rs" 2>/dev/null | grep -q .; then
    fail "group id reappeared"
fi
if grep -rq "flow_cgroup_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "group helper reappeared"
fi
if grep -rq 'cgroup\.bpf\.h' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "group include reappeared"
fi
if grep -rq "scx_bpf_task_cgroup\|bpf_cgroup_release" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "group kfunc reappeared"
fi
if grep -rq "cgroup_init\|cgroup_exit\|cgroup_move\|cgroup_set_weight" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "group op reappeared"
fi
grep -q "flow_calc_lat_cri(p, t)" "${ENQ_HDR}" || fail "lat cri use missing"
grep -q "flow_task_weight(p, t)" "${DISP_HDR}" || fail "task weight dispatch missing"
grep -q "flow_share_live" "${FAIR_HDR}" || fail "share live missing"
grep -q "flow_eff_w" "${FAIR_HDR}" || fail "eff combine missing"
grep -q "flow_nice_weight" "${FAIR_HDR}" || fail "nice helper missing"
grep -q "flow_task_weight" "${FAIR_HDR}" || fail "task weight helper missing"
grep -q "n < s ? n : s" "${FAIR_HDR}" || fail "clamp combine missing"
grep -q "FLOW_CGROUP_WEIGHT_MIN" "${FAIR_HDR}" || fail "share clamp missing"
grep -q "FLOW_CGROUP_WEIGHT_MAX" "${FAIR_HDR}" || fail "share clamp missing"
if grep -q "SCX_DHQ_STRAND_A\|SCX_DHQ_STRAND_B" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "strand reappeared"
fi
if grep -q "first strand" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "strand prose reappeared"
fi
grep -q "due time" "${ENQ_HDR}" || fail "due order prose missing"
grep -q "flow_calc_slice" "${FAIR_HDR}" || fail "calc slice missing"
grep -q "flow_calc_slice(t," "${ENQ_HDR}" || fail "calc slice use missing"
if grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${ENQ_HDR}" 2>/dev/null; then
    fail "fixed slice reappeared"
fi
if grep -q "flow_run_slice" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "run slice reappeared"
fi
grep -q "flow_kick_idle_only" "${ENQ_HDR}" || fail "idle kick missing"
grep -q "flow_try_preempt" "${ENQ_HDR}" || fail "soft yield missing"
grep -q "est_stopping_clk" "${ENQ_HDR}" || fail "stop claim missing"
grep -q "nr_preempt" "${ENQ_HDR}" || fail "preempt count missing"
grep -q "near stop" "${ENQ_HDR}" || fail "soft yield prose missing"
# Soft yield stays CAS only with no IPI. All wakes stay idle only except
# the soft yield path which claims the victim stop stamp with no kick.
# Two idle kick sites stay in the shared helper plus select direct.
# Select kicks the won idle CPU after a LOCAL insert and the shared
# enqueue path reuses the helper.
[ "$(grep -rh "SCX_KICK_PREEMPT" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "0" ] || fail "ipi preempt reappeared"
[ "$(grep -rh "SCX_KICK_IDLE" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "2" ] || fail "idle kick sites drifted"
grep -q "with no IPI" "${ENQ_HDR}" || fail "no ipi prose missing"
grep -q "yields soft" "${SRC_DIR}/src/bpf/intf.h" || fail "soft prose missing"
grep -q "Fallback" "${ENQ_HDR}" || fail "fallback prose missing"
grep -q "scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ" "${ENQ_HDR}" || fail "fallback fifo insert missing"
if grep -q "insert_vtime.*FALLBACK\|FALLBACK.*insert_vtime" "${ENQ_HDR}" 2>/dev/null; then
    fail "fallback vtime insert reappeared"
fi
if grep -q "FLOW_EDF\|flow_edf" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "edf reappeared"
fi
if grep -q "FLOW_LAT\|flow_lat" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "lat reappeared"
fi
if grep -q "FLOW_PRIO\|flow_prio" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "prio reappeared"
fi
if grep -q "remain_ns\|deadline_ns\|est_ns" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "old task field reappeared"
fi
if grep -q "wait_hold\|home_stick\|home_cpu" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "old hold reappeared"
fi
if grep -q "hyst\|hog" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "old burst reappeared"
fi
if grep -q "slack" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "slack reappeared"
fi
if grep -q "FLOW_HIST_LEN\|FLOW_LAT_KINDS\|FLOW_LAT_BUCKETS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "hist const reappeared"
fi
if grep -e "GAP" -e "NORM" -e "BATCH" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null | grep -v "FLOW_KICK_GAP_NS" | grep -q .; then
    fail "old band const reappeared"
fi
if grep -q "edf\|slack" "${SRC_DIR}/src/bpf/enqueue.bpf.h" "${DISP_HDR}" 2>/dev/null; then
    case "$(grep "edf\|slack" "${SRC_DIR}/src/bpf/enqueue.bpf.h" "${DISP_HDR}")" in
        *) fail "edf text reappeared" ;;
    esac
fi
if grep -rn "flow_lst_\|FLOW_LST_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead lst prefix reappeared"
fi
if grep -rn "lst_escape\|lst_urgent\|lst_hold\|lst_preempt\|lst_overdue" "${SRC_DIR}" 2>/dev/null | grep -v target; then
    fail "dead stats prefix reappeared"
fi
[ ! -e "${SRC_DIR}/src/bpf/lst.bpf.h" ] && true || fail "dead header reappeared"
if grep -q "float" "${FAIR_HDR}" 2>/dev/null; then
    fail "float reappeared"
fi
if grep -qi "float" "${ENQ_HDR}" "${DISP_HDR}" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "float reappeared in queue"
fi
if grep -q "double" "${FAIR_HDR}" 2>/dev/null; then
    fail "double reappeared"
fi
grep -q "due time" "${SRC_DIR}/src/bpf/intf.h" || fail "due field missing"
grep -q "flow_calc_when_to_run" "${FAIR_HDR}" || fail "when run missing"
grep -q "flow_try_preempt" "${ENQ_HDR}" || fail "soft yield missing"

# Due order stays with one yield per run and idle fast path.
# Each running instance yields at most once per generation, idle targets
# take idle wakes, and a runnable yield with no burn still moves time.
grep -q "Each running instance yields at most once" "${SRC_DIR}/src/bpf/intf.h" || fail "yield bound prose missing"
grep -q "At most one yield per run" "${ENQ_HDR}" || fail "enqueue yield bound prose missing"
grep -q "scx_bpf_test_and_clear_cpu_idle(tgt)" "${ENQ_HDR}" || fail "idle consume missing"
if grep -q "flow_kick_vd\|flow_vd_for\|rs->pad.*kick\|flow_fair_cap_add" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    # flow_calc_slice plus flow_calc_when_to_run are the only vd path now
    if grep -q "flow_kick_vd" "${SRC_DIR}/src/bpf" 2>/dev/null; then
        fail "stale vd kick reappeared"
    fi
fi

# Stats keep order with thirteen counters at one hundred four bytes.
grep -q "kick_preempt" "${SRC_DIR}/src/bpf/intf.h" || fail "preempt field missing"
grep -q "orphan_kick" "${SRC_DIR}/src/bpf/intf.h" || fail "orphan field missing"
grep -q "hol_forward" "${SRC_DIR}/src/bpf/intf.h" || fail "forward field missing"
grep -q "overrun" "${SRC_DIR}/src/bpf/intf.h" || fail "overrun field missing"
grep -q "blocked" "${SRC_DIR}/src/bpf/intf.h" || fail "blocked field missing"
grep -q "kick_preempt" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "orphan_kick" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "hol_forward" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "kick_preempt" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "orphan_kick" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "hol_forward" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
if grep -q "edf_escape\|edf_urgent\|edf_hold\|edf_preempt\|edf_overdue" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "old stats name reappeared"
fi
if grep -q "edf_escape\|edf_urgent\|edf_hold\|edf_preempt\|edf_overdue" "${SRC_DIR}/src/stats.rs" 2>/dev/null; then
    fail "old stats name reappeared"
fi
if grep -q "edf_escape\|edf_urgent\|edf_hold\|edf_preempt\|edf_overdue" "${SRC_DIR}/src/metrics.rs" 2>/dev/null; then
    fail "old stats name reappeared"
fi
if grep -q "extra_award\|total_quanta\|domino_penalty" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "old award reappeared"
fi
if grep -q "extra_award\|total_quanta\|domino_penalty" "${SRC_DIR}/src/stats.rs" 2>/dev/null; then
    fail "old award reappeared"
fi
if grep -q "extra_award\|total_quanta\|domino_penalty" "${SRC_DIR}/src/metrics.rs" 2>/dev/null; then
    fail "old award reappeared"
fi
if grep -q "LatMetrics\|lat_hist\|fold_lat_val\|collect_lat" "${SRC_DIR}/src/stats.rs" "${SRC_DIR}/src/metrics.rs" "${SRC_DIR}/src/run.rs" "${SRC_DIR}/src/main.rs" 2>/dev/null; then
    fail "lat wiring reappeared"
fi
if grep -q '"lat"' "${SRC_DIR}/src/stats.rs" 2>/dev/null; then
    fail "lat endpoint reappeared"
fi

# Tables stay scoped with four maps and seven headers.
# Task storage plus LLC stats plus CPU seed plus one timer. Top keeps
# thirteen counters. DSQ ids stay at 0x1000 plus 0x2000 plus 0x6100 with
# quoted headers at seven plus ops at fifteen.
[ "$(grep -rh 'SEC(".maps")' "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "4" ] || fail "maps count drifted"
[ "$(grep -c 'include "' "${SRC_DIR}/src/bpf/main.bpf.c" | tr -d ' ')" = "7" ] || fail "headers count drifted"
if grep -q '<lib/rbtree.h>' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "rbtree angled reappeared for honest BST"
fi
if grep -q '<lib/edq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" 2>/dev/null; then
    fail "angled edq reappeared"
fi
if grep -q '<lib/dhq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" 2>/dev/null; then
    fail "angled dhq reappeared"
fi
grep -q '<lib/topology.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled topo missing"
grep -q 'add_source.*lib/arena.bpf.c' "${SRC_DIR}/build.rs" || fail "arena source missing"
if grep -q 'add_source.*lib/edq.bpf.c' "${SRC_DIR}/build.rs" 2>/dev/null; then
    fail "edq lib reappeared"
fi
grep -q 'add_source.*lib/rbtree.bpf.c' "${SRC_DIR}/build.rs" || fail "rbtree lib missing"
if grep -q 'add_source.*lib/dhq.bpf.c' "${SRC_DIR}/build.rs" 2>/dev/null; then
    fail "dhq lib reappeared"
fi
grep -q 'add_source.*lib/topology.bpf.c' "${SRC_DIR}/build.rs" || fail "topo lib missing"
grep -q 'add_source.*lib/minheap.bpf.c' "${SRC_DIR}/build.rs" || fail "minheap lib missing"
grep -q 'add_source.*lib/sdt_task.bpf.c' "${SRC_DIR}/build.rs" || fail "task lib missing"
grep -q 'compile_link_gen' "${SRC_DIR}/build.rs" || fail "link helper missing"
if grep -q "lat_hist" "${SRC_DIR}/src/bpf/maps.bpf.h" 2>/dev/null; then
    fail "wait map reappeared"
fi
if grep -q "flow_wait_allow\|flow_home_stick" "${SRC_DIR}/src/bpf/maps.bpf.h" 2>/dev/null; then
    fail "old global reappeared"
fi

# Ops stay at fifteen with no probe added.
[ "$(grep -rh "BPF_STRUCT_OPS" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "15" ] || fail "ops count drifted"

# DSQ drain keeps thirteen bounded loops with no new program.
# Five scans live in select for the constrained pick plus tier order.
# Eight scans live in dispatch for the DSQ drain plus timer plus init
# plus exit, all bounded by the live CPU plus LLC counts.
[ "$(grep -rh "bpf_for" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "13" ] || fail "loop budget drifted"

# Queues are one per CPU plus one per LLC plus fallback with due time order.
# DSQ ids stay at 0x1000 plus 0x2000 plus 0x6100. Moves go to local with
# topology drain plus continuation for a runnable prev. No RB plus no EDQ
# plus no DHQ plus no arena queue remains.
grep -q "FLOW_FALLBACK_CAP = 1024ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "fallback cap missing"
grep -q "FLOW_QUEUE_CAP = 64ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "queue cap missing"
grep -q "FLOW_CPU_DSQ_BASE = 0x1000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "cpu base missing"
grep -q "FLOW_LLC_DSQ_BASE = 0x2000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "llc base missing"
grep -q "FLOW_FALLBACK_DSQ = 0x6100ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "fallback base missing"
grep -q "scx_bpf_dsq_insert" "${ENQ_HDR}" || fail "dsq insert missing"
grep -q "scx_bpf_dsq_move_to_local" "${DISP_HDR}" || fail "dsq move missing"
grep -q "task_ctx_stor" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "task stor missing"
grep -q "llc_stats_stor" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "llc stor missing"
grep -q "cpu_ctx_stor" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "cpu stor missing"
grep -q "update_timer" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "timer missing"
grep -q "topo_all" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo tree missing"
grep -q "topo_contains" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo test missing"
grep -q "topo_cpu_to_llc_id" "${DISP_HDR}" || fail "topo llc missing"
grep -q "topo_all" "${DISP_HDR}" || fail "dispatch topo missing"
grep -q "FLOW_CGROUP_WEIGHT_DFLT = 100ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "weight default missing"
if grep -q "SCX_DHQ_\|scx_dhq_\|SCX_DHQ_INF_CAPACITY" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dhq reappeared"
fi
if grep -q "scx_edq_\|flow_edq\|flow_rb_\|FLOW_RB_\|scx_static_alloc\|scx_alloc\|flow_arena_task" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale rb reappeared"
fi
if grep -q "flow_dhq_\|flow_topo_\|FLOW_DHQ_BASE\|FLOW_DHQ_STRAND\|FLOW_DHQ_MODE\|FLOW_DHQ_PERCPU\|FLOW_DHQ_MAX" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "own queue helper reappeared"
fi
if grep -q "FLOW_LLC_BASE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "llc base reappeared"
fi
if grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "stale fair base reappeared"
fi
if grep -q 'include "edf.bpf.h"\|include "lat.bpf.h"\|include "sjf.bpf.h"\|include "edf.bpf.h"' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale include reappeared"
fi

# Dead helpers stay removed. The per LLC prio queue helper has no caller
# and must not return.
if grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead queue helper reappeared"
fi
if grep -rq "flow_combine\|flow_cgroup_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead weight helper reappeared"
fi

# Direct dispatch clears its mark before any queue gauge moves so a
# locally dispatched task never counts twice.
grep -q "already queued to local" "${ENQ_HDR}" || fail "direct dispatch order missing"
grep -q "not queued twice" "${ENQ_HDR}" || fail "direct dispatch prose missing"

# Dispatch drops the queue gauge on the enqueue LLC read from the
# task, with no scan. The count always comes from the task.
if grep -q "have_owner" "${DISP_HDR}" 2>/dev/null; then
    fail "fallback scan state reappeared"
fi
grep -q "flow_queued_dec" "${DISP_HDR}" || fail "queue dec missing"
if grep -q 'bpf_for(li, 0, FLOW_MAX_LLCS)' "${DISP_HDR}" 2>/dev/null; then
    fail "fallback scan reappeared"
fi

# Queued gauge keeps the floor through a saturating atomic step with
# no plain store when the compare loop loses.
if grep -q "st->queued = last - 1" "${SRC_DIR}/src/bpf/stats.bpf.h" 2>/dev/null; then
    fail "queued direct store reappeared"
fi
grep -q "__sync_fetch_and_sub(&st->queued" "${SRC_DIR}/src/bpf/stats.bpf.h" || fail "queued saturating step missing"

# Installer provenance states the mirror and upstream share one commit.
if ! grep -q "matches the upstream" "${INST}" 2>/dev/null; then
    fail "fork provenance comment missing"
fi

# Fallback stays FIFO only with no vtime insert naming the fallback queue.
if grep -q "insert_vtime.*FALLBACK\|FALLBACK.*insert_vtime" "${ENQ_HDR}" 2>/dev/null; then
    fail "fallback vtime insert reappeared"
fi
grep -q "scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ" "${ENQ_HDR}" || fail "fallback fifo insert missing"

# Moves go straight to local with no peek. Dispatch reads the node
# from the tree with no per-CPU walk. Select checks the mask on every
# tier with live checks.
grep -q "scx_bpf_dsq_move_to_local" "${DISP_HDR}" || fail "move missing"
if grep -q "scx_bpf_dsq_peek" "${DISP_HDR}" 2>/dev/null; then
    fail "peek reappeared"
fi
if grep -q "tcc->llc_id\|t2->llc_id" "${DISP_HDR}" 2>/dev/null; then
    fail "dead cpu scan reappeared"
fi
grep -q "topo_contains" "${DISP_HDR}" || fail "tree order missing"
grep -q "flow_cpu_allowed" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "pick clamp missing"

# Task init clears vtime through compat with no group resolve.
if grep -q "scx_bpf_task_cgroup" "${DISP_HDR}" 2>/dev/null; then
    fail "task cgroup reappeared"
fi
grep -q "scx_bpf_task_set_dsq_vtime" "${DISP_HDR}" || fail "dsq vtime setter missing"

# Thread shape defaults on so a missed seed stays conservative.
# Userspace seeds the data section before load with the kernel default on miss.
grep -q "flow_smt_enabled = 1" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "smt default missing"
grep -q "data_data" "${SRC_DIR}/src/run.rs" || fail "smt seed drifted"
grep -q "flow_smt_enabled" "${SRC_DIR}/src/run.rs" || fail "smt seed drifted"
if grep -q "bss_data.*flow_smt_enabled" "${SRC_DIR}/src/run.rs" 2>/dev/null; then
    fail "smt seed section drifted"
fi

# Cluster width stays heuristic with sorted LLC order.
grep -q "Width four is a heuristic" "${SRC_DIR}/src/topology.rs" || fail "cluster heuristic missing"
grep -q "fn core_cluster" "${SRC_DIR}/src/topology.rs" || fail "known helper missing"
grep -q "cluster_id != -1" "${SRC_DIR}/src/topology.rs" || fail "sentinel narrow missing"
if grep -q "cluster_id >= 0" "${SRC_DIR}/src/topology.rs" 2>/dev/null; then
    fail "broad unknown reappeared"
fi
[ "$(sed '/#\[cfg(test)/,$d' "${SRC_DIR}/src/topology.rs" | grep -c "cpu_ccx(topo, &llc_ids)" | tr -d ' ')" = "5" ] || fail "seed display split"
[ "$(sed '/#\[cfg(test)/,$d' "${SRC_DIR}/src/topology.rs" | grep -c "llc_ids.sort_unstable" | tr -d ' ')" = "5" ] || fail "fallback order drifted"
if grep -q "tie favor kept" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "stale tie favor reappeared"
fi

# Dispatch liveness keeps every queued task reachable. Due time orders
# the drain, slices stay bounded with no zero insert, and kicks never
# take minus one without a skip.
grep -q "due time" "${DISP_HDR}" || fail "due order prose missing"
grep -q "FLOW_SLICE_MIN_NS" "${DISP_HDR}" || fail "dispatch slice floor missing"
grep -q "FLOW_SLICE_MAX_NS" "${DISP_HDR}" || fail "dispatch slice max missing"
grep -q "flow_calc_slice" "${ENQ_HDR}" || fail "enqueue calc slice missing"
grep -q "flow_calc_slice" "${DISP_HDR}" || fail "dispatch calc slice missing"
if grep -q "dsq_insert(p, (u64)FLOW_FALLBACK_DSQ, 0" "${DISP_HDR}" "${ENQ_HDR}" 2>/dev/null; then
    fail "zero slice insert reappeared"
fi
if grep -q "dsq_insert(p, SCX_DSQ_LOCAL, 0" "${DISP_HDR}" 2>/dev/null; then
    fail "zero slice insert reappeared"
fi
grep -q "if (tgt < 0)" "${ENQ_HDR}" || fail "kick minus one guard missing"
if grep -q "kick_cpu(-1" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "raw kick minus one reappeared"
fi
grep -q "owner < 0" "${DISP_HDR}" || fail "orphan owner check missing"
if grep -q "flow_rekick_unrunnable\|saw_unrunnable\|Forward slots hash by\|dedup key\|victim &" "${DISP_HDR}" 2>/dev/null; then
    fail "stale forward reappeared"
fi

# Scheduler README stays minimal with knob-free latency score plus virtual
# deadline DSQ plus direct dispatch plus slice continuation plus near stop
# claim plus timer decay.
grep -q "knob-free" "${SRC_DIR}/README.md" || fail "readme knob missing"
grep -q "virtual deadline" "${SRC_DIR}/README.md" || fail "readme deadline missing"
grep -q "DSQ" "${SRC_DIR}/README.md" || fail "readme dsq missing"
grep -q "direct local dispatch" "${SRC_DIR}/README.md" || fail "readme dispatch missing"
grep -q "slice continuation" "${SRC_DIR}/README.md" || fail "readme continue missing"
grep -q "near stop claim" "${SRC_DIR}/README.md" || fail "readme soft missing"
grep -q "fixed order" "${SRC_DIR}/README.md" || fail "readme order missing"
grep -q "L1 > L2 > L3" "${SRC_DIR}/README.md" || fail "readme tier missing"
grep -q "half on a timer" "${SRC_DIR}/README.md" || fail "readme timer missing"
if grep -q "EEVDF\|EWMA\|HRRN\|binary search\|burst-aware" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme stale model reappeared"
fi
if grep -qi "mate\|strand\|warm" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme strand reappeared"
fi
if grep -q " vd" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme short vd reappeared"
fi

# Task plus running plus sys plus seed sizes stay locked.
grep -q '_Static_assert(sizeof(struct flow_task_ctx) == 104' "${SRC_DIR}/src/bpf/intf.h" || fail "task size missing"
grep -q '_Static_assert(sizeof(struct flow_running_state) == 96' "${SRC_DIR}/src/bpf/intf.h" || fail "running size missing"
grep -q '_Static_assert(sizeof(struct flow_sys_stat) == 56' "${SRC_DIR}/src/bpf/intf.h" || fail "sys size missing"
grep -q '_Static_assert(sizeof(struct flow_cpu_ctx) == 16' "${SRC_DIR}/src/bpf/intf.h" || fail "seed size missing"
grep -q 'flow_task_ctx>() == 104' "${SRC_DIR}/src/run.rs" || fail "run task assert missing"
grep -q 'flow_running_state>() == 96' "${SRC_DIR}/src/run.rs" || fail "run running assert missing"
grep -q 'flow_sys_stat>() == 56' "${SRC_DIR}/src/run.rs" || fail "run sys assert missing"
grep -q 'flow_cpu_ctx>() == 16' "${SRC_DIR}/src/run.rs" || fail "run seed assert missing"
if grep -q "216\|48.*running.*assert\|flow_rb_node\|flow_arena_task\|flow_rb_entry" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    # 216 plus 48 plus RB plus arena belong to the old BST design
    if grep -q '_Static_assert(sizeof(struct flow_task_ctx) == 216' "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
        fail "stale task size reappeared"
    fi
    if grep -q "flow_rb_node\|flow_arena_task" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
        fail "stale rb reappeared"
    fi
fi

# Bucket ladder stays in sync with identical thresholds.
grep -q "kb <= 32U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 32 missing"
grep -q "kb <= 48U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 48 missing"
grep -q "kb <= 256U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 256 missing"
grep -q "kb <= 512U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 512 missing"
grep -q "kb <= 1024U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 1024 missing"
grep -q "kb <= 8192U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 8192 missing"
grep -q "kb <= 16384U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 16384 missing"
grep -q "kb <= 32768U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 32768 missing"
grep -q "kb <= 98304U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 98304 missing"
grep -q "kb <= 524288U" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf ladder 524288 missing"
grep -q "kb <= 32" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 32 missing"
grep -q "kb <= 48" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 48 missing"
grep -q "kb <= 256" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 256 missing"
grep -q "kb <= 512" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 512 missing"
grep -q "kb <= 1024" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 1024 missing"
grep -q "kb <= 8192" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 8192 missing"
grep -q "kb <= 16384" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 16384 missing"
grep -q "kb <= 32768" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 32768 missing"
grep -q "kb <= 98304" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 98304 missing"
grep -q "kb <= 524288" "${SRC_DIR}/src/topology.rs" || fail "rust ladder 524288 missing"
grep -q "Mirrors cache_bucket in topology.rs" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf mirror missing"
grep -q "Keep both in sync" "${SRC_DIR}/src/bpf/intf.h" || fail "bpf sync prose missing"

# Dead BPF helpers stay removed with no new dead code.
if grep -q "flow_is_primary" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead primary reappeared"
fi
if grep -q "flow_cpu_l2bkt\|flow_cpu_l3bkt\|flow_cache_larger\|flow_cpu_view" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead bucket helper reappeared"
fi
if grep -q "flow_fb_inc" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead fb inc reappeared"
fi
if grep -q "flow_combine\|flow_cgroup_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead weight helper reappeared"
fi
if grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead queue helper reappeared"
fi

# Loop plus map plus ops budgets stay locked.
[ "$(grep -rh "bpf_for" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "13" ] || fail "loop budget drifted"
[ "$(grep -rh 'SEC(".maps")' "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "4" ] || fail "maps count drifted"
[ "$(grep -rh "BPF_STRUCT_OPS" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "15" ] || fail "ops count drifted"

# LLC counters keep order with thirteen at one hundred four bytes.
pre_at="$(grep -n "kick_preempt" "${SRC_DIR}/src/bpf/intf.h" | head -n 1 | cut -d: -f1)"
idle_at="$(grep -n "kick_idle" "${SRC_DIR}/src/bpf/intf.h" | head -n 1 | cut -d: -f1)"
skip_at="$(grep -n "kick_skip" "${SRC_DIR}/src/bpf/intf.h" | head -n 1 | cut -d: -f1)"
[ "${pre_at}" -lt "${idle_at}" ] && [ "${idle_at}" -lt "${skip_at}" ] || fail "kick counter order drifted"

# Timer only power with 100 percent busy plus 50 percent idle.
grep -q "flow_cpuperf_mark" "${DISP_HDR}" || fail "power mark missing"
grep -q "SCX_CPUPERF_ONE" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "power max missing"
grep -q "SCX_CPUPERF_ONE / 2" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "power half missing"
grep -q "never touches a busy core" "${DISP_HDR}" || fail "power timer prose missing"
if awk '/void BPF_STRUCT_OPS\(flow_stopping/,/^}/' "${DISP_HDR}" | grep -q "flow_cpuperf_mark(cpu, true)" 2>/dev/null; then
    fail "stopping drop reappeared"
fi

# No forbidden schedulers plus no float plus no GPU plus no design labels.
if grep -rni "lavd\|eevdf\|cfs\|rustland\|bpfland" "${SRC_DIR}/src/bpf" "${SRC_DIR}/README.md" 2>/dev/null | grep -q .; then
    fail "forbidden scheduler reappeared"
fi
if grep -q "float" "${FAIR_HDR}" 2>/dev/null; then
    fail "float reappeared"
fi
if grep -qi "float" "${ENQ_HDR}" "${DISP_HDR}" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "float reappeared in queue"
fi
if grep -rqi "gpu" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "gpu hint reappeared"
fi
if grep -rnE "H-[0-9]|SEC-[0-9]|PERF-[0-9]|FR-[0-9]|REQ-[0-9]|HIGH-[0-9]|MED-[0-9]|LOW-[0-9]" "${SRC_DIR}/README.md" "${SRC_DIR}/src/bpf" "${SRC_DIR}/src/"*.rs "${REPO_DIR}/README.md" 2>/dev/null | grep -q .; then
    fail "design label reappeared"
fi
if grep -rn "—" "${SRC_DIR}/README.md" "${SRC_DIR}/src/bpf" "${SRC_DIR}/src/"*.rs "${REPO_DIR}/README.md" 2>/dev/null | grep -q .; then
    fail "em dash reappeared"
fi
if grep -q ";" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "scx README semicolon reappeared"
fi


echo "guard tests passed"