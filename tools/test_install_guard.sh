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
[ "${want}" = "5.2.5" ] || fail "version not at 5.2.5"

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
    "src/bpf/maps.bpf.h" \
    "src/bpf/select.bpf.h" \
    "src/bpf/stats.bpf.h"; do
    [ -s "${SRC_DIR}/${need_flow}" ] || fail "flow scaffold missing ${need_flow}"
    grep -q "Galih Tama" "${SRC_DIR}/${need_flow}" || fail "flow rationale missing ${need_flow}"
done
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
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "dc8b743542efda36a0fb3db3c2046f7c3acd931c04ae8f96cc6ff1a5cc2d2659" ] || fail "scx README drifted"
[ "$(wc -l < "${SRC_DIR}/README.md" | tr -d ' ')" = "10" ] || fail "scx README lines drifted"

# Harness stays present with report fields and no workload change.
[ -s "${REPO_DIR}/tools/edf_harness/harness.c" ] || fail "harness scaffold missing harness.c"
[ -s "${REPO_DIR}/tools/edf_harness/run.sh" ] || fail "harness scaffold missing run.sh"
grep -q "probe_p99_us" "${REPO_DIR}/tools/edf_harness/harness.c" || fail "harness p99 missing"
grep -q "spill" "${REPO_DIR}/tools/edf_harness/harness.c" || fail "harness spill missing"
grep -q "occupancy" "${REPO_DIR}/tools/edf_harness/harness.c" || fail "harness occupancy missing"
grep -q "probe_p99_us" "${REPO_DIR}/tools/edf_harness/run.sh" || fail "harness report missing p99"

# Hint probe stays userspace only with no BPF hook and no vd write.
[ -s "${REPO_DIR}/tools/nn_hint/nn_hint.py" ] || fail "hint scaffold missing nn_hint.py"
[ -s "${REPO_DIR}/tools/nn_hint/README.md" ] || fail "hint scaffold missing README"
if grep -q "scx_bpf_\|bpf_task_storage\|dsq_vtime" "${REPO_DIR}/tools/nn_hint/nn_hint.py" 2>/dev/null; then
    fail "hint BPF hook reappeared"
fi
grep -q "never writes vd\|never writes" "${REPO_DIR}/tools/nn_hint/README.md" || fail "hint vd prose missing"
grep -q "no faster claim\|no scheduler" "${REPO_DIR}/tools/nn_hint/README.md" || fail "hint claim prose missing"

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

# Topology keeps local first drain with dual strands. The drain keeps
# own CPU first then mates then rest of same LLC then same node then
# remote then fallback, dual strands in vd order with earliest head
# first, the pick keeps the hint when allowed else the first near
# target, and ties keep the first CPU in fixed order.
grep -q "drains its own queue" "${DISP_HDR}" || fail "cache drain prose missing"
grep -q "both strands" "${DISP_HDR}" || fail "dual strand prose missing"
grep -q "earlier vd" "${DISP_HDR}" || fail "merge order prose missing"
grep -q "mates in the same LLC" "${DISP_HDR}" || fail "mate prose missing"
grep -q "vd order" "${DISP_HDR}" || fail "vd order prose missing"
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

# Busy cores run at max with idle cores at half through one set call.
# The call never sends zero and never steers placement, and no other
# frequency call steers placement.
grep -q "never steers" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "freq prose missing"
grep -q "never steers" "${DISP_HDR}" || fail "freq dispatch prose missing"
grep -q "never sends zero" "${DISP_HDR}" || fail "freq never zero prose missing"
grep -q "scx_bpf_cpuperf_set" "${DISP_HDR}" || fail "cpuperf set missing"
grep -q "SCX_CPUPERF_ONE" "${DISP_HDR}" || fail "cpuperf max missing"
grep -q "SCX_CPUPERF_ONE / 2" "${DISP_HDR}" || fail "cpuperf half missing"
if grep -q "cpuperf" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
    if ! grep -q "cpuperf_set" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null; then
        fail "freq call not set only"
    fi
fi
if grep "scx_bpf_cpufreq\|bpf_cpufreq\|freq_set\|perf_set" "${SRC_DIR}/src/bpf/select.bpf.h" "${DISP_HDR}" 2>/dev/null | grep -v "scx_bpf_cpuperf_set" | grep -q .; then
    fail "freq steer reappeared"
fi

# Changelog plus design histories remain public in prior commits; tip carries no docs blobs.

# Pure vd ordering with dual strands and fixed integers and no knob. Vd adds
# the share step to the floored time, queue key is vd across both strands
# with FIFO fallback, and shared enqueues kick for preempt on an earlier
# vd else idle with a skip otherwise. Stopping plus tick charge burnt time
# with no extra state. No float plus no new divide is kept.
FAIR_HDR="${SRC_DIR}/src/bpf/fair.bpf.h"
ENQ_HDR="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "FLOW_SLICE_MIN_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice quantum missing"
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "flow_fair_step" "${FAIR_HDR}" || fail "fair step missing"
grep -q "flow_fair_cap_add" "${FAIR_HDR}" || fail "cap add missing"
grep -q "flow_fair_charge" "${FAIR_HDR}" || fail "fair charge missing"
grep -q "flow_seq_floor" "${FAIR_HDR}" || fail "floor helper missing"
grep -q "flow_vd_for" "${FAIR_HDR}" || fail "vd helper missing"
grep -q "flow_vd_for" "${ENQ_HDR}" || fail "vd use missing"
grep -q "flow_seq_floor" "${ENQ_HDR}" || fail "floor use missing"
grep -q "flow_cgroup_lookup" "${ENQ_HDR}" || fail "cgroup lookup missing"
grep -q "SCX_DHQ_STRAND_A" "${ENQ_HDR}" || fail "strand use missing"
grep -q "SCX_DHQ_STRAND_B" "${ENQ_HDR}" || fail "second strand missing"
grep -q "SCX_DHQ_STRAND_B" "${DISP_HDR}" || fail "merge strand missing"
grep -q "flow_warm_target" "${ENQ_HDR}" || fail "warm retarget missing"
grep -q "same LLC" "${ENQ_HDR}" || fail "warm llc prose missing"
grep -q "flow_try_insert_dhq" "${ENQ_HDR}" || fail "strand retry missing"
grep -q "vb < va" "${DISP_HDR}" || fail "merge compare missing"
grep -q "flow_cpu_ccx" "${DISP_HDR}" || fail "mate compare missing"
grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${ENQ_HDR}" || fail "fixed slice missing"
grep -q "flow_kick_idle_only" "${ENQ_HDR}" || fail "idle kick missing"
grep -q "flow_kick_vd" "${ENQ_HDR}" || fail "vd kick missing"
grep -q "new_vd < run_vd" "${ENQ_HDR}" || fail "strict compare missing"
grep -q "SCX_KICK_PREEMPT" "${ENQ_HDR}" || fail "preempt kick missing"
if grep -q "SCX_KICK_PREEMPT" "${DISP_HDR}" 2>/dev/null; then
    fail "preempt kick drifted to dispatch"
fi
[ "$(grep -rl "SCX_KICK_PREEMPT" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "1" ] || fail "preempt kick not enqueue only"
grep -q "flow_stat_inc(llc, 6)" "${ENQ_HDR}" || fail "preempt count missing"
if grep -q "flow_stat_inc(llc, 6)" "${DISP_HDR}" 2>/dev/null; then
    fail "preempt count drifted to dispatch"
fi
grep -q "FIFO" "${ENQ_HDR}" || fail "fifo prose missing"
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
if grep -q "GAP\|NORM\|BATCH" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
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
grep -q "vd" "${SRC_DIR}/src/bpf/intf.h" || fail "vd field missing"
grep -q "flow_vd_for" "${FAIR_HDR}" || fail "vd helper missing"
grep -q "flow_kick_vd" "${ENQ_HDR}" || fail "vd kick missing"

# Dual strands stay with one kick per run and idle fast path.
# Each run kicks at most once, idle targets take idle wakes, each
# vd win kicks for preempt, and a runnable yield with no burn still
# moves time.
grep -q "Each running instance kicks at most once" "${SRC_DIR}/src/bpf/intf.h" || fail "kick bound prose missing"
grep -q "Each running instance kicks at most once" "${ENQ_HDR}" || fail "enqueue kick bound prose missing"
grep -q "scx_bpf_test_and_clear_cpu_idle(tgt)" "${ENQ_HDR}" || fail "idle consume missing"
grep -q "rs->pad" "${ENQ_HDR}" || fail "kick cookie missing"
grep -q "flow_fair_cap_add" "${DISP_HDR}" || fail "yield advance missing"

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

# Tables stay scoped with four maps and eight headers.
# The base tables hold task plus cpu plus llc plus weight with per CPU
# queue handles. Top keeps thirteen counters. Queues come from upstream,
# so quoted headers stay at eight with ops at sixteen.
[ "$(grep -rh 'SEC(".maps")' "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "4" ] || fail "maps count drifted"
[ "$(grep -c 'include "' "${SRC_DIR}/src/bpf/main.bpf.c" | tr -d ' ')" = "8" ] || fail "headers count drifted"
grep -q '<lib/dhq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled dhq missing"
grep -q '<lib/topology.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled topo missing"
grep -q 'add_source.*lib/arena.bpf.c' "${SRC_DIR}/build.rs" || fail "arena source missing"
grep -q 'add_source.*lib/dhq.bpf.c' "${SRC_DIR}/build.rs" || fail "dhq lib missing"
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

# Ops stay at sixteen with no probe added.
[ "$(grep -rh "BPF_STRUCT_OPS" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "16" ] || fail "ops count drifted"

# Queues are one per CPU plus fallback with vd order and insertion ties.
# Fair scales base by share with a per LLC floor. Vd sets the order with
# a strict preempt on an earlier vd. Wakes go preempt on a vd win else
# idle with a skip otherwise. Queues use the upstream library with per
# CPU placement and FIFO fallback. Depth caps at ten for ten millis max.
grep -q "FLOW_FALLBACK_CAP = 1024ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "fallback cap missing"
grep -q "SCX_DHQ_STRAND_A" "${ENQ_HDR}" || fail "strand use missing"
grep -q "SCX_DHQ_MODE_BALANCED" "${DISP_HDR}" || fail "mode use missing"
grep -q "scx_dhq_create_balanced" "${DISP_HDR}" || fail "queue create missing"
grep -q "10ULL" "${DISP_HDR}" || fail "percpu cap missing"
if grep -q "256ULL" "${DISP_HDR}" 2>/dev/null; then
    fail "old percpu cap reappeared"
fi
grep -q "SCX_DHQ_MODE_BALANCED, 1ULL" "${DISP_HDR}" || fail "imbalance cap missing"
grep -q "scx_dhq_insert_vtime" "${ENQ_HDR}" || fail "queue insert missing"
grep -q "scx_dhq_pop_strand" "${DISP_HDR}" || fail "queue pop missing"
grep -q "scx_dhq_peek_strand" "${DISP_HDR}" || fail "queue peek missing"
grep -q "flow_dhqs" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "queue handle missing"
grep -q "topo_all" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo tree missing"
grep -q "TOPO_FOR_EACH_NODE" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo walk missing"
grep -q "topo_contains" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "topo test missing"
grep -q "topo_cpu_to_llc_id" "${DISP_HDR}" || fail "topo llc missing"
grep -q "topo_all" "${DISP_HDR}" || fail "dispatch topo missing"
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
    fail "dead queue helper reappeared"
fi
if grep -q "FLOW_LLC_BASE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "llc base reappeared"
fi
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "flow_fair_charge" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "fair charge missing"
grep -q "flow_seq_floor" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "floor helper missing"
grep -q "flow_cgroup_lookup" "${SRC_DIR}/src/bpf/cgroup.bpf.h" || fail "cgroup live lookup missing"
grep -q "insertion order" "${ENQ_HDR}" || fail "insertion order missing"
grep -q "fallback queue" "${ENQ_HDR}" || fail "fallback path missing"
grep -q "kick_idle" "${SRC_DIR}/src/bpf/intf.h" || fail "idle count missing"
grep -q "kick_skip" "${SRC_DIR}/src/bpf/intf.h" || fail "skip count missing"
if grep -q 'include "edf.bpf.h"' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "edf include reappeared"
fi
if grep -q 'include "lat.bpf.h"' "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "lat include reappeared"
fi
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
if ! grep -q "without the queued bit" "${ENQ_HDR}" 2>/dev/null; then
    fail "local ownership order missing"
fi

# Fallback dispatch drops the gauge on the enqueue LLC read from the
# task, with no scan. The count always comes from the task.
if grep -q "have_owner" "${DISP_HDR}" 2>/dev/null; then
    fail "fallback scan state reappeared"
fi
grep -q "flow_queued_dec(vllc)" "${DISP_HDR}" || fail "fallback owner dec missing"
if grep -q 'bpf_for(li, 0, FLOW_MAX_LLCS)' "${DISP_HDR}" 2>/dev/null; then
    fail "fallback scan reappeared"
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
if grep -q "insert_vtime.*FALLBACK\|FALLBACK.*insert_vtime" "${ENQ_HDR}" 2>/dev/null; then
    fail "fallback vtime insert reappeared"
fi
grep -q "scx_bpf_dsq_insert(p, (u64)FLOW_FALLBACK_DSQ" "${ENQ_HDR}" || fail "fallback fifo insert missing"

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

# Thread shape defaults on so a missed seed stays conservative.
# Userspace seeds the data section before load with the kernel default on miss.
grep -q "flow_smt_enabled = 1" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "smt default missing"
grep -q "data_data" "${SRC_DIR}/src/run.rs" || fail "smt seed drifted"
grep -q "flow_smt_enabled" "${SRC_DIR}/src/run.rs" || fail "smt seed drifted"
if grep -q "bss_data.*flow_smt_enabled" "${SRC_DIR}/src/run.rs" 2>/dev/null; then
    fail "smt seed section drifted"
fi

# Cluster width stays heuristic with the tie favor kept on shared threads.
# Width four splits larger clusters without ever merging distant cores,
# and only the fast pick is gated on single threads.
grep -q "Width four is a heuristic" "${SRC_DIR}/src/topology.rs" || fail "cluster heuristic missing"
grep -q "tie favor kept" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "tie favor prose missing"

# Dispatch liveness keeps every queued task reachable. Dual strands
# drain with no count bail, slices stay at the floor with no zero
# insert, kicks never take minus one without a skip, forward slots stay
# per victim with the fallback reserved, and a tail re-kick covers heads
# that could not run here.
if grep -q "if (!ca && !cb)" "${DISP_HDR}" 2>/dev/null; then
    fail "nr_queued bail reappeared"
fi
grep -q "Dual strand drain" "${DISP_HDR}" || fail "dual strand prose missing"
grep -q "break fairness" "${DISP_HDR}" || fail "fairness prose missing"
grep -q "slice = (u64)FLOW_SLICE_MIN_NS" "${DISP_HDR}" || fail "dispatch slice floor missing"
grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${ENQ_HDR}" || fail "enqueue slice floor missing"
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
grep -q "victim &" "${DISP_HDR}" || fail "forward slot missing"
grep -q "(u32)FLOW_MAX_LLCS" "${DISP_HDR}" || fail "fallback slot missing"
grep -q "flow_rekick_unrunnable" "${DISP_HDR}" || fail "re-kick helper missing"
grep -q "saw_unrunnable" "${DISP_HDR}" || fail "unrunnable flag missing"
grep -q "its own forward slot" "${DISP_HDR}" || fail "forward slot prose missing"
grep -q "dead head is dropped" "${DISP_HDR}" || fail "dead pop prose missing"
grep -q "without the dedup check" "${DISP_HDR}" || fail "re-kick prose missing"
grep -q "until the mask widens" "${DISP_HDR}" || fail "fallback reliance prose missing"

# Scheduler README stays minimal with deadline plus per-CPU plus FIFO
# plus fixed slice plus idle plus preempt plus restart plus dual strand
# plus ten plus overflow plus tail target plus offline hint.
grep -q "deadline" "${SRC_DIR}/README.md" || fail "readme deadline missing"
grep -q "per-CPU" "${SRC_DIR}/README.md" || fail "readme percpu missing"
grep -q "FIFO" "${SRC_DIR}/README.md" || fail "readme fifo missing"
grep -q "fixed" "${SRC_DIR}/README.md" || fail "readme fixed missing"
grep -q "1ms" "${SRC_DIR}/README.md" || fail "readme slice missing"
grep -q "idle" "${SRC_DIR}/README.md" || fail "readme idle missing"
grep -q "preempt" "${SRC_DIR}/README.md" || fail "readme preempt missing"
grep -q "restart" "${SRC_DIR}/README.md" || fail "readme restart missing"
grep -q "strand" "${SRC_DIR}/README.md" || fail "readme strand missing"
grep -q "10 tasks" "${SRC_DIR}/README.md" || fail "readme cap missing"
grep -q "10ms" "${SRC_DIR}/README.md" || fail "readme bound missing"
grep -q "aspirational" "${SRC_DIR}/README.md" || fail "readme ideal missing"
grep -q "overflow" "${SRC_DIR}/README.md" || fail "readme overflow missing"
grep -q "tail" "${SRC_DIR}/README.md" || fail "readme tail missing"
grep -q "offline" "${SRC_DIR}/README.md" || fail "readme hint missing"

# No classifier plus no average estimator returns with no float divide.
if grep -qi "ewma" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "average estimator reappeared"
fi
if grep -q "classifier" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    if ! grep -q "cluster hint" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
        fail "classifier reappeared"
    fi
fi
if grep -rn "float\|double" "${SRC_DIR}/src/bpf/enqueue.bpf.h" "${SRC_DIR}/src/bpf/dispatch.bpf.h" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "float outside fair reappeared"
fi

echo "guard tests passed"
