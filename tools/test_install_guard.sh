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
[ "${want}" = "5.2.17" ] || fail "version not at 5.2.17"

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
grep -q '<lib/edq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled edq missing"
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
# Cache idle keeps every wake idle only with no preempt site.
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "f481825ce8cd558658214d157a7e84594fb0439914b780f4e17f89e096dc3259" ] || fail "scx README drifted"
[ "$(wc -l < "${SRC_DIR}/README.md" | tr -d ' ')" = "23" ] || fail "scx README lines drifted"

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
grep -q 'rm -rf "${DEST}/src/bpf/lib"' "${INST}" || fail "lib remove missing"
grep -q 'rm -rf "${DEST}/lib"' "${INST}" || fail "top lib remove missing"
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

# Topology keeps local first drain in deadline order. The drain keeps
# own CPU first then same LLC then same node then remote then fallback,
# each queue in deadline order, the pick keeps the hint
# when allowed else the first near target, and ties keep the first CPU
# in fixed order.
grep -q "drains its own queue" "${DISP_HDR}" || fail "cache drain prose missing"
grep -q "deadline order" "${DISP_HDR}" || fail "deadline order prose missing"
if grep -q "first strand" "${DISP_HDR}" 2>/dev/null; then
    fail "strand prose reappeared"
fi
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

# Pure deadline ordering with fixed integers and no knob. Deadline adds
# the burst scaled nice step to the floored time, queue key is deadline
# with FIFO fallback, and shared enqueues kick for preempt on
# an earlier deadline else idle with a skip otherwise. Stopping plus tick charge
# burnt time with burst as the only extra state. No float plus no new divide
# is kept.
FAIR_HDR="${SRC_DIR}/src/bpf/fair.bpf.h"
ENQ_HDR="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "FLOW_SLICE_MIN_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice quantum missing"
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "flow_fair_step" "${FAIR_HDR}" || fail "fair step missing"
grep -q "flow_fair_cap_add" "${FAIR_HDR}" || fail "cap add missing"
grep -q "flow_fair_charge" "${FAIR_HDR}" || fail "fair charge missing"
grep -q "flow_nice_table" "${FAIR_HDR}" || fail "nice table missing"
grep -q "flow_nice_weight" "${FAIR_HDR}" || fail "nice weight missing"
if grep -rq "flow_combine" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "combine reappeared"
fi
[ "$(grep -rh "flow_nice_weight" "${ENQ_HDR}" "${DISP_HDR}" | wc -l | tr -d ' ')" = "4" ] || fail "nice use drifted"
grep -q "flow_seq_floor" "${FAIR_HDR}" || fail "floor helper missing"
grep -q "flow_vd_for" "${FAIR_HDR}" || fail "vd helper missing"
grep -q "flow_vd_for" "${ENQ_HDR}" || fail "vd use missing"
grep -q "flow_seq_floor" "${ENQ_HDR}" || fail "floor use missing"
# Burst run length scales the vd step with shift only moves and a
# bounded floor. The vd takes three args with the burst in the middle
# and the floor cap stays at one base step. Pure deadline order keeps
# the floored time plus the burst scaled nice step with no wakeup nudge.
grep -q "FLOW_SLICE_FLOOR_NS = 62500ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "burst floor missing"
grep -q "burst_ns" "${SRC_DIR}/src/bpf/intf.h" || fail "burst field missing"
grep -q "flow_burst_clamp" "${FAIR_HDR}" || fail "burst clamp missing"
grep -q "flow_burst_update" "${FAIR_HDR}" || fail "burst update missing"
grep -q "flow_vd_for(s64 floored, u64 burst_ns, u32 w)" "${FAIR_HDR}" || fail "vd arg drifted"
grep -q "b >> 1" "${FAIR_HDR}" || fail "burst half shift missing"
grep -q "b >> 2" "${FAIR_HDR}" || fail "burst quarter shift missing"
grep -q "flow_vd_for(floored, READ_ONCE(t->burst_ns), w)" "${ENQ_HDR}" || fail "burst vd use missing"
grep -q "flow_fair_cap_add(last, (u64)FLOW_FAIR_BASE_NS)" "${FAIR_HDR}" || fail "floor cap missing"
grep -q "flow_fair_cap_add(floored, 1)" "${FAIR_HDR}" || fail "vd floor missing"
# Pure proxy keeps deadline order with no wakeup nudge. Any assist helper
# plus wakeup branch plus eighth shift must not return.
if grep -q "flow_vd_wakeup_assist" "${FAIR_HDR}" "${ENQ_HDR}" 2>/dev/null; then
    fail "wakeup assist reappeared"
fi
if grep -q "step >> 3" "${FAIR_HDR}" 2>/dev/null; then
    fail "assist shift reappeared"
fi
if grep -q "SCX_ENQ_WAKEUP" "${ENQ_HDR}" 2>/dev/null; then
    fail "wakeup branch reappeared"
fi
# No overload control with bare admit plus FIFO fallback and no reclaim.
# Admit checks room plus cap only. A full target keeps the newcomer in
# FIFO with no evict and no band. Stopping plus tick keep burst plus run
# with no saved reclaim.
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
grep -q "nr < (u64)FLOW_QUEUE_CAP" "${ENQ_HDR}" || fail "bare admit missing"
grep -q "with no evict" "${ENQ_HDR}" || fail "no evict prose missing"
grep -q "with no evict" "${SRC_DIR}/src/bpf/intf.h" || fail "no evict prose missing"
grep -q "no reclaim" "${SRC_DIR}/src/bpf/intf.h" || fail "no reclaim prose missing"
grep -q "no reclaim" "${DISP_HDR}" || fail "no reclaim prose missing"
grep -q "total_used" "${DISP_HDR}" || fail "burst run missing"
grep -q "flow_burst_update(READ_ONCE(t->burst_ns), total_used, cur, runnable)" "${DISP_HDR}" || fail "stop burst missing"
grep -q "flow_vd_for(nv, rem, w)" "${DISP_HDR}" || fail "tick vd missing"
grep -q "flow_vd_for(nv, (u64)FLOW_SLICE_MIN_NS, w)" "${DISP_HDR}" || fail "tick floor vd missing"
[ "$(grep -c "t->burst_ns = (u64)FLOW_SLICE_MIN_NS" "${DISP_HDR}" | tr -d ' ')" = "3" ] || fail "burst seed drifted"
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
grep -q "flow_nice_weight(p)" "${ENQ_HDR}" || fail "nice use missing"
grep -q "flow_nice_weight(p)" "${DISP_HDR}" || fail "nice dispatch use missing"
grep -q "flow_share_live" "${FAIR_HDR}" || fail "share live missing"
grep -q "flow_eff_w" "${FAIR_HDR}" || fail "eff combine missing"
grep -q "flow_share_live(p)" "${ENQ_HDR}" || fail "share live use missing"
grep -q "flow_eff_w(flow_nice_weight(p)" "${ENQ_HDR}" || fail "eff use missing"
grep -q "flow_eff_w(flow_nice_weight(p)" "${DISP_HDR}" || fail "eff dispatch use missing"
grep -q "n < s ? n : s" "${FAIR_HDR}" || fail "clamp combine missing"
grep -q "FLOW_CGROUP_WEIGHT_MIN" "${FAIR_HDR}" || fail "share clamp missing"
grep -q "FLOW_CGROUP_WEIGHT_MAX" "${FAIR_HDR}" || fail "share clamp missing"
if grep -q "SCX_DHQ_STRAND_A\|SCX_DHQ_STRAND_B" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "strand reappeared"
fi
if grep -q "first strand" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "strand prose reappeared"
fi
grep -q "deadline order" "${ENQ_HDR}" || fail "deadline order prose missing"
grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${ENQ_HDR}" || fail "fixed slice missing"
grep -q "flow_kick_idle_only" "${ENQ_HDR}" || fail "idle kick missing"
grep -q "flow_kick_vd" "${ENQ_HDR}" || fail "vd kick missing"
grep -q "new_vd < run_vd" "${ENQ_HDR}" || fail "strict compare missing"
# Cache idle keeps every wake idle only with no preempt site.
# The deadline win path counts idle on a win with skips otherwise.
if grep -rq "SCX_KICK_PREEMPT" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "preempt kick reappeared"
fi
grep -q "kicks idle on a win" "${ENQ_HDR}" || fail "idle win prose missing"
grep -q "wakes idle only" "${SRC_DIR}/src/bpf/intf.h" || fail "idle only prose missing"
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

# Deadline order stays with one kick per run and idle fast path.
# Each run kicks at most once, idle targets take idle wakes, each
# deadline win kicks idle, and a runnable yield with no burn still
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

# Tables stay scoped with three maps and seven headers.
# The base tables hold task plus cpu plus llc with one embedded
# queue per CPU in arena memory. Top keeps thirteen counters. Queues
# come from upstream, so quoted headers stay at seven with ops at thirteen.
# The arena task map is infra and not counted here.
[ "$(grep -rh 'SEC(".maps")' "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "3" ] || fail "maps count drifted"
[ "$(grep -c 'include "' "${SRC_DIR}/src/bpf/main.bpf.c" | tr -d ' ')" = "7" ] || fail "headers count drifted"
grep -q '<lib/edq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled edq missing"
if grep -q '<lib/dhq.h>' "${SRC_DIR}/src/bpf/main.bpf.c" 2>/dev/null; then
    fail "angled dhq reappeared"
fi
grep -q '<lib/topology.h>' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "angled topo missing"
grep -q 'add_source.*lib/arena.bpf.c' "${SRC_DIR}/build.rs" || fail "arena source missing"
grep -q 'add_source.*lib/edq.bpf.c' "${SRC_DIR}/build.rs" || fail "edq lib missing"
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

# Ops stay at thirteen with no probe added.
[ "$(grep -rh "BPF_STRUCT_OPS" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "13" ] || fail "ops count drifted"

# Cache idle drain keeps six bounded loops with no new program.
# One scan lives in select for the seed pick plus one scan for the first
# allowed fallback. Four victim passes live in dispatch for same group
# plus same LLC plus same node plus remote.
[ "$(grep -rh "bpf_for" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "6" ] || fail "loop budget drifted"

# Queues are one per CPU plus fallback with deadline order and insertion ties.
# Fair scales base by nice weight with a per LLC floor. Deadline sets the order with
# a strict earlier deadline win. Wakes go idle only with a skip otherwise.
# Queues use the upstream library with per
# CPU placement and FIFO fallback. Queues hold bounded at 64 total.
grep -q "FLOW_FALLBACK_CAP = 1024ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "fallback cap missing"
grep -q "FLOW_QUEUE_CAP = 64ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "queue cap missing"
if grep -q "SCX_DHQ_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dhq const reappeared"
fi
if grep -q "scx_dhq_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dhq helper reappeared"
fi
if grep -q "SCX_DHQ_INF_CAPACITY" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "unbounded cap reappeared"
fi
if grep -q "10ULL" "${DISP_HDR}" 2>/dev/null; then
    fail "stale cap reappeared"
fi
if grep -q "256ULL" "${DISP_HDR}" 2>/dev/null; then
    fail "old percpu cap reappeared"
fi
grep -q "scx_static_alloc" "${DISP_HDR}" || fail "queue alloc missing"
grep -q "flow_edqs" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "queue handle missing"
if grep -q "flow_dhqs" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "old queue handle reappeared"
fi
grep -q "scx_edq_insert" "${ENQ_HDR}" || fail "queue insert missing"
grep -q "scx_edq_pop" "${DISP_HDR}" || fail "queue pop missing"
grep -q "scx_edq_peek_hold" "${DISP_HDR}" || fail "queue peek missing"
grep -q "scx_edq_nr_queued" "${ENQ_HDR}" || fail "queue cap check missing"
grep -q "scx_edq_try_remove" "${DISP_HDR}" || fail "queue remove missing"
grep -q "scx_edq_task_init" "${DISP_HDR}" || fail "task init missing"
grep -q "scx_edq_task_detach" "${DISP_HDR}" || fail "task detach missing"
grep -q "scx_edq_task_drop" "${DISP_HDR}" || fail "task drop missing"
grep -q "scx_edq_task_fini" "${DISP_HDR}" || fail "task fini missing"
grep -q "scx_task_alloc" "${DISP_HDR}" || fail "arena alloc missing"
grep -q "scx_task_free" "${DISP_HDR}" || fail "arena free missing"
grep -rq "__scx_task_data" "${SRC_DIR}/src/bpf" || fail "arena lookup missing"
grep -q "flow_edq_for_cpu" "${ENQ_HDR}" || fail "queue helper missing"
grep -q "flow_edq_deadline" "${ENQ_HDR}" || fail "deadline helper missing"
grep -q "flow_try_move_edq" "${DISP_HDR}" || fail "move helper missing"
grep -q "flow_arena_task" "${SRC_DIR}/src/bpf/intf.h" || fail "arena task missing"
grep -q "flow_arena_task" "${SRC_DIR}/src/run.rs" || fail "arena size missing"
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
grep -q "FLOW_CGROUP_WEIGHT_DFLT = 100ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "weight default missing"
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

# Dead helpers stay removed. The per LLC prio queue helper has no caller
# and must not return.
if grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "dead queue helper reappeared"
fi
if grep -rq "flow_task_weight\|flow_combine\|flow_cgroup_" "${SRC_DIR}/src/bpf" 2>/dev/null; then
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

# Select rechecks the winning pick against the current mask.
grep -q "flow_cpu_allowed(best, p)" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "pick clamp missing"

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

# Cluster width stays heuristic with the tie favor kept on shared threads.
# Width four splits larger clusters without ever merging distant cores,
# and only the fast pick is gated on single threads.
grep -q "Width four is a heuristic" "${SRC_DIR}/src/topology.rs" || fail "cluster heuristic missing"
grep -q "tie favor kept" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "tie favor prose missing"

# Seed plus display share one known-or-fallback helper with sorted LLC order.
# Known means neither minus one nor 65535. The display count delegates to
# the seed helper, so both report the same groups on every host.
grep -q "fn core_cluster" "${SRC_DIR}/src/topology.rs" || fail "known helper missing"
grep -q "cluster_id != -1" "${SRC_DIR}/src/topology.rs" || fail "sentinel narrow missing"
if grep -q "cluster_id >= 0" "${SRC_DIR}/src/topology.rs" 2>/dev/null; then
    fail "broad unknown reappeared"
fi
[ "$(grep -c "cpu_ccx(topo, &llc_ids)" "${SRC_DIR}/src/topology.rs" | tr -d ' ')" = "3" ] || fail "seed display split"
[ "$(grep -c "llc_ids.sort_unstable" "${SRC_DIR}/src/topology.rs" | tr -d ' ')" = "3" ] || fail "fallback order drifted"

# Dispatch liveness keeps every queued task reachable. Deadline order
# drains in deadline order, slices stay at the floor with no zero
# insert, kicks never take minus one without a skip, forward slots stay
# per victim with the fallback reserved, and a tail re-kick covers heads
# that could not run here.
grep -q "deadline order" "${DISP_HDR}" || fail "deadline order prose missing"
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
# plus fixed slice plus idle plus preempt plus restart plus burst vd.
grep -q "burst" "${SRC_DIR}/README.md" || fail "readme burst missing"
grep -q "deadline" "${SRC_DIR}/README.md" || fail "readme deadline missing"
grep -q "per-CPU" "${SRC_DIR}/README.md" || fail "readme percpu missing"
grep -q "FIFO" "${SRC_DIR}/README.md" || fail "readme fifo missing"
grep -q "fixed" "${SRC_DIR}/README.md" || fail "readme fixed missing"
grep -q "1ms" "${SRC_DIR}/README.md" || fail "readme slice missing"
grep -q "idle" "${SRC_DIR}/README.md" || fail "readme idle missing"
grep -q "preempt" "${SRC_DIR}/README.md" || fail "readme preempt missing"
grep -q "restart" "${SRC_DIR}/README.md" || fail "readme restart missing"
if grep -q "least queued\|most loaded" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme load reappeared"
fi
if grep -qi "mate\|strand\|warm" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme strand reappeared"
fi
if grep -q "without bound" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme unbounded reappeared"
fi
if grep -q "without a bound" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme unbounded reappeared"
fi
if grep -q "no bound" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme unbounded reappeared"
fi
if grep -q "10 tasks" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme stale cap reappeared"
fi
if grep -q "10ms" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme stale bound reappeared"
fi
if grep -q "aspirational" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme ideal reappeared"
fi

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

# No load balancing remains with constrained placement plus topology drain.
# Enqueue joins the queue of the constrained target with no least pick
# and no waiting counts. Dispatch drains in topology order with no
# busiest pick and no warm queue. Every queue insert uses deadline order
# with FIFO fallback for rejects.
if grep -q "flow_pick_least\|flow_pick_busiest" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "load pick reappeared"
fi
if grep -q "flow_qcnt\|flow_warm_strand\|flow_try_insert_dhq\|flow_try_insert_edq\|flow_is_same_node\|warm_only" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "load state reappeared"
fi
if grep -q "qcpu" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stored queue reappeared"
fi
if grep -q "SCX_DHQ_STRAND_B\|SCX_DHQ_STRAND_A" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "strand reappeared"
fi
if grep -q "best_mate\|vb < va\|both strands\|Dual strand" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "merge state reappeared"
fi
if grep -q "mate" "${ENQ_HDR}" "${DISP_HDR}" "${SRC_DIR}/src/bpf/intf.h" "${SRC_DIR}/src/bpf/maps.bpf.h" 2>/dev/null; then
    fail "mate bias reappeared"
fi
grep -q "flow_constrained_target(task_cpu, p)" "${ENQ_HDR}" || fail "constrained place missing"
grep -q "flow_edq_for_cpu(tgt)" "${ENQ_HDR}" || fail "queue helper use missing"
grep -q "saw_unrunnable)" "${DISP_HDR}" || fail "drain signature missing"
grep -q "FLOW_QUEUE_CAP" "${SRC_DIR}/src/bpf/intf.h" || fail "queue cap prose missing"
grep -q "bounded at 64" "${SRC_DIR}/src/bpf/intf.h" || fail "bounded prose missing"
grep -q "bounded at 64" "${ENQ_HDR}" || fail "enqueue bounded prose missing"
grep -q "bounded at 64" "${DISP_HDR}" || fail "dispatch bounded prose missing"
grep -q "bounded at 64" "${SRC_DIR}/src/bpf/maps.bpf.h" || fail "maps bounded prose missing"
grep -q "bounded at 64" "${SRC_DIR}/src/bpf/main.bpf.c" || fail "main bounded prose missing"
if grep -q "SCX_DHQ_INF_CAPACITY" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "unbounded cap reappeared"
fi
if grep -q "without bound" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "unbounded prose reappeared"
fi
if grep -q "without a bound" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "unbounded prose reappeared"
fi
if grep -q "no bound" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "unbounded prose reappeared"
fi
if grep -q "at most ten tasks" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "stale bounded prose reappeared"
fi

# Single queue per CPU stays with no second index.
# One embedded queue per CPU in arena memory, so a second dimension
# on the handle table must not return.
if grep -rn "flow_edqs\[.*\]\[" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "2-D queue handles reappeared"
fi
if grep -rn "flow_dhqs\[.*\]\[" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "old 2-D handles reappeared"
fi

# Ordered drain stays fail closed with forward wakes. Each CPU drains
# its own queue first, then same LLC, then same node, then
# remote, then fallback, with one forward wake per unrunnable head.
grep -q "flow_drain_cpu" "${DISP_HDR}" || fail "drain helper missing"
grep -q "flow_try_move_edq" "${DISP_HDR}" || fail "move helper missing"

# Safe but accurate run length path with unknown fallback.
# Storage holds eight pairs plus range plus flag plus sum under the
# task storage cap with integer only and bounded scans. Close runs on
# sleep only with saturating add plus prune past the window and a
# freeze on a zero or backward clock. Enqueue reads the cached flag
# with no clock and no scan. Steady tasks price by the kept max with
# the shared charge path and one slice quanta, unknown tasks keep the
# burst path with no long hold.
grep -q "FLOW_RUN_WIN_NS = 30000000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "run window missing"
grep -q "FLOW_RUN_SPAN_NS = 4000000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "run span missing"
grep -q "FLOW_RUN_NEED = 4ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "run need missing"
grep -q "run_dur\[8\]" "${SRC_DIR}/src/bpf/intf.h" || fail "run dur missing"
grep -q "run_stamp\[8\]" "${SRC_DIR}/src/bpf/intf.h" || fail "run stamp missing"
grep -q "run_known" "${SRC_DIR}/src/bpf/intf.h" || fail "run known missing"
grep -q "run_total" "${SRC_DIR}/src/bpf/intf.h" || fail "run total missing"
grep -q "flow_run_reset" "${FAIR_HDR}" || fail "run reset missing"
grep -q "flow_run_add" "${FAIR_HDR}" || fail "run add missing"
grep -q "flow_run_prune" "${FAIR_HDR}" || fail "run prune missing"
grep -q "flow_run_close" "${FAIR_HDR}" || fail "run close missing"
grep -q "flow_run_recalc" "${FAIR_HDR}" || fail "run recalc missing"
grep -q "flow_run_ref" "${FAIR_HDR}" || fail "run ref missing"
grep -q "flow_run_eff" "${FAIR_HDR}" || fail "run eff missing"
grep -q "flow_run_vd" "${FAIR_HDR}" || fail "run vd missing"
grep -q "flow_run_slice" "${FAIR_HDR}" || fail "run slice missing"
grep -q "min_d >> 3" "${FAIR_HDR}" || fail "run band missing"
grep -q "& 7U" "${FAIR_HDR}" || fail "run mask missing"
grep -q "bpf_ktime_get_ns" "${DISP_HDR}" || fail "run clock missing"
grep -q "flow_run_add(t, used)" "${DISP_HDR}" || fail "run stop add missing"
grep -q "flow_run_close(t, now)" "${DISP_HDR}" || fail "run close use missing"
grep -q "flow_run_prune(t, now)" "${DISP_HDR}" || fail "run prune use missing"
grep -q "flow_run_reset(t)" "${DISP_HDR}" || fail "run reset use missing"
grep -q "flow_run_eff(ref" "${ENQ_HDR}" || fail "run eff use missing"
grep -q "flow_run_vd(floored, eff, w)" "${ENQ_HDR}" || fail "run vd use missing"
grep -q "flow_run_slice(ref)" "${ENQ_HDR}" || fail "run slice use missing"
grep -q "known && ref" "${ENQ_HDR}" || fail "run gate use missing"
grep -q "flow_vd_for(floored, READ_ONCE(t->burst_ns), w)" "${ENQ_HDR}" || fail "unknown vd missing"
if grep -rn "float\|double" "${SRC_DIR}/src/bpf/enqueue.bpf.h" "${SRC_DIR}/src/bpf/dispatch.bpf.h" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "float outside fair reappeared"
fi
# Unknown fallback keeps fixed slice with no long hold.
if grep -q "30000000000ULL.*slice\|slice.*30000000000ULL" "${ENQ_HDR}" "${DISP_HDR}" 2>/dev/null; then
    fail "long slice reappeared"
fi
grep -q "flow_run_slice" "${FAIR_HDR}" || fail "slice clamp missing"
# Scheduler README keeps virtual deadline in full words with run prose.
grep -q "Virtual deadline" "${SRC_DIR}/README.md" || fail "readme virtual deadline missing"
grep -q "kept" "${SRC_DIR}/README.md" || fail "readme kept missing"
grep -q "Unknown tasks keep the burst path" "${SRC_DIR}/README.md" || fail "readme unknown missing"
if grep -q " vd" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme short vd reappeared"
fi

# Family A stays excluded with no slow field plus helpers.
# Task storage stays at two hundred sixteen bytes with the run ring
# plus range plus flag plus sum and no slow path. The four Family A
# names stay absent from BPF with no revert needed.
if grep -rq "slow" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "slow reappeared"
fi
if grep -rq "idle_decay\|idle-decay" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "idle decay reappeared"
fi
if grep -rq "fast_known\|fast-known" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "fast known reappeared"
fi
if grep -rq "max_stamp\|max-stamp" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "max stamp reappeared"
fi
grep -q "run_min" "${SRC_DIR}/src/bpf/intf.h" || fail "run min missing"
grep -q "run_max" "${SRC_DIR}/src/bpf/intf.h" || fail "run max missing"
grep -q "run_head" "${SRC_DIR}/src/bpf/intf.h" || fail "run head missing"
grep -q "run_pruned" "${SRC_DIR}/src/bpf/intf.h" || fail "run pruned missing"
grep -q "run_pad" "${SRC_DIR}/src/bpf/intf.h" || fail "run pad missing"
# Narrowed deadline fit keeps deadline plus reference plus lag plus reweight
# plus floor plus slice with no count divide and no retroactive update.
# Reference keeps max with shift only. Lag rides the stored time with clamp.
# Reweight applies at enqueue time only.
grep -q "Virtual deadline" "${SRC_DIR}/src/bpf/intf.h" || fail "narrowed deadline prose missing"
grep -q "Virtual deadline" "${FAIR_HDR}" || fail "narrowed vd prose missing"
grep -q "flow_fair_charge" "${DISP_HDR}" || fail "narrowed charge missing"
if grep -rq "retroactive" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "retroactive reappeared"
fi
if grep -rq "count_divide\|count-divide" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "count divide reappeared"
fi
if grep -q "count / \|/ count" "${FAIR_HDR}" 2>/dev/null; then
    fail "count divide reappeared"
fi
# Scheduler README keeps virtual deadline in full words with run prose.
grep -q "Virtual deadline" "${SRC_DIR}/README.md" || fail "readme virtual deadline missing"
grep -q "kept" "${SRC_DIR}/README.md" || fail "readme kept missing"
grep -q "Unknown tasks keep the burst path" "${SRC_DIR}/README.md" || fail "readme unknown missing"
if grep -q " vd" "${SRC_DIR}/README.md" 2>/dev/null; then
    fail "readme short vd reappeared"
fi
# Kick keeps one per run with separable skips plus a freshness check.
# Each miss counts the same skip counter with no new counter.
# The win rechecks mask plus liveness plus generation plus due time
# before the preempt, so a stale kick never hits a fresh run.
grep -q "flow_kick_idle_only" "${ENQ_HDR}" || fail "idle kick missing"
grep -q "flow_kick_vd" "${ENQ_HDR}" || fail "vd kick missing"
grep -q "Freshness check after the win" "${ENQ_HDR}" || fail "kick freshness missing"
grep -q "fresh_gen" "${ENQ_HDR}" || fail "kick gen recheck missing"
grep -q "fresh_vd" "${ENQ_HDR}" || fail "kick vd recheck missing"
grep -q "Misses split by cause" "${ENQ_HDR}" || fail "kick cause prose missing"

# Kicks count every miss with an LLC recheck after the win.
grep -q "rllc = READ_ONCE(rs->llc_id)" "${ENQ_HDR}" || fail "llc recheck missing"

# Edge cases stay closed with no slice or deadline drift on wake paths.
# Wake helpers never write task time or slice or run state. The win path
# keeps the single kick token with skips otherwise. Exiting tasks keep
# the one microsecond slice. Init fails closed on a missing tree or an
# over bound CPU count.
wake_block() {
    awk '/^static __always_inline void flow_kick_idle_only\(/,/^}/' "${ENQ_HDR}"
    awk '/^static __always_inline void flow_kick_vd\(/,/^}/' "${ENQ_HDR}"
    awk '/^static __always_inline void flow_forward_from_peeked\(/,/^}/' "${DISP_HDR}"
    awk '/^static __always_inline void flow_rekick_unrunnable\(/,/^}/' "${DISP_HDR}"
}
if wake_block | grep -q "slice_rem *=\|->vd *=\|->vtime *=\|burst_ns *=\|run_dur\|run_total\|run_min\|run_max\|run_head\|run_known\|run_stamp\|run_pruned\|run_pad\|->llc_id *=\|->flags *=\|->gen *=" 2>/dev/null; then
    fail "wake path writes task state"
fi
# The wake path never mutates run or burst state. Enqueue reads the kept
# max plus the burst path only.
if grep -q "flow_run_add\|flow_run_close\|flow_run_prune\|flow_burst_update" "${ENQ_HDR}" 2>/dev/null; then
    fail "run mutate leaked into enqueue"
fi
# Deadline keys saturate negatives at zero.
grep -q "flow_edq_deadline" "${ENQ_HDR}" || fail "deadline helper missing"
grep -q "if (vd < 0)" "${ENQ_HDR}" || fail "deadline saturate drifted"
# The floor keeps uniqueness through the compare swap plus one.
grep -q "want = last + 1" "${FAIR_HDR}" || fail "floor uniqueness missing"
grep -q "__sync_val_compare_and_swap(&flow_llc_seq" "${FAIR_HDR}" || fail "floor swap missing"
# Exiting tasks keep the one microsecond slice with no zero insert.
grep -q "FLOW_EXIT_SLICE_NS = 1000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "exit slice missing"
# Init fails closed on a missing tree or an over bound count.
grep -q "topology tree missing" "${DISP_HDR}" || fail "tree guard missing"
grep -q "return -ENODEV" "${DISP_HDR}" || fail "tree fail closed missing"
grep -q "CPU count over bound" "${DISP_HDR}" || fail "count guard missing"
grep -q "return -E2BIG" "${DISP_HDR}" || fail "count fail closed missing"
# Mask change on a queued task never rewrites the due time.
if awk '/flow_set_cpumask/,/^}/' "${DISP_HDR}" | grep -q "t->vd\|t->vtime\|burst_ns" 2>/dev/null; then
    fail "mask path rewrites deadline"
fi

# Affinity stays closed on every path. The constrained target keeps the
# hint only when allowed plus live. The pick rechecks the winner with a
# first allowed fallback. Every kick rechecks mask plus liveness. Pinned
# plus exiting plus maskless tasks keep FIFO fallback. The tier orders
# allowed plus live CPUs only and never widens the mask.
grep -q "flow_cpu_allowed(hint, p) && flow_cpu_live" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "hint gate missing"
grep -q "return flow_first_allowed(p)" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "pick fallback missing"
grep -q "cpus_ptr" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "mask null guard missing"
grep -q "nr_cpus_allowed" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "pin detect missing"
grep -q "is_migration_disabled" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "migration pin missing"
grep -q "bpf_cpumask_test_cpu" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "mask test missing"
grep -q "bpf_cpumask_first" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "first mask read missing"
grep -q "no_cpu" "${ENQ_HDR}" || fail "maskless path missing"
grep -q "PF_EXITING" "${ENQ_HDR}" || fail "exiting path missing"
grep -q "flow_stat_inc(qllc, 11)" "${DISP_HDR}" || fail "orphan count missing"
grep -q "flow_cpu_allowed(owner, p)" "${DISP_HDR}" || fail "owner recheck missing"
grep -q "flow_ccx_match(use_ccx, flow_cpu_ccx(victim), my_ccx)" "${DISP_HDR}" || fail "group match call missing"

# Cache idle orders the drain by cache tier with no size map and no seed change.
# The group tier read plus the tier match plus the empty check stay
# allowlisted by exact name. Any other cache helper fails closed here.
grep -q "flow_cpu_ccx" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "cache tier read missing"
grep -q "flow_ccx_match" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "cache tier match missing"
grep -q "flow_edq_empty" "${DISP_HDR}" || fail "empty check missing"
grep -q "L1>L2>L3" "${DISP_HDR}" || fail "tier order missing"
grep -q "L1 greater than L2 greater than L3" "${DISP_HDR}" || fail "tier prose missing"
grep -q "L1>L2>L3" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "pick tier order missing"
grep -q "Empty queues skip" "${DISP_HDR}" || fail "empty skip prose missing"
grep -q "Both known" "${DISP_HDR}" || fail "known gate prose missing"
grep -q "fixed order" "${DISP_HDR}" || fail "fixed order prose missing"
if grep -rq "flow_cpu_l2b" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "cache size helper reappeared"
fi
if grep -rq "flow_l2_larger\|flow_l3_prefer" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "cache compare reappeared"
fi
if grep -rq "TOPO_FOR_EACH_CORE" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "core walk reappeared"
fi
if grep -q "l2_bucket\|l3_bucket\|cache_cls" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "cache seed reappeared"
fi
if grep -q "seed_topology_with\|lstopo_caches" "${SRC_DIR}/src/run.rs" "${SRC_DIR}/src/topology.rs" 2>/dev/null; then
    fail "cache seed reappeared in userspace"
fi
if grep -q "larger caches first" "${SRC_DIR}/README.md" "${DISP_HDR}" 2>/dev/null; then
    fail "cache order drifted"
fi

# Unknown group stays distinct with no zero conflation. The sentinel reads
# as all ones with both known gate plus fixed order cover plus allowed live
# bounds kept on every path.
grep -q "FLOW_CCX_UNKNOWN" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "unknown sentinel missing"
grep -q "0xFFFFFFFF" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "sentinel value missing"
grep -q "never match" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "unknown prose missing"
grep -q "all ones" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "sentinel prose missing"
grep -q "all ones" "${DISP_HDR}" || fail "dispatch sentinel prose missing"
if grep -q "return use && cx == hint" "${SRC_DIR}/src/bpf/select.bpf.h" 2>/dev/null; then
    fail "zero conflation reappeared"
fi

# Shared header drains by cache tier with fallback and ordered prose.
grep -q "same cache group" "${SRC_DIR}/src/bpf/intf.h" || fail "intf tier prose missing"
grep -q "L1>L2>L3" "${SRC_DIR}/src/bpf/intf.h" || fail "intf tier order missing"
grep -q "L1 greater" "${SRC_DIR}/src/bpf/intf.h" || fail "intf tier words missing"
grep -q "then fallback last" "${SRC_DIR}/src/bpf/intf.h" || fail "intf fallback prose missing"

# First allowed scans past an offline head with mask plus live bounds.
grep -q "Scan the mask" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "fallback scan prose missing"
grep -q "no usable CPU fall back" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "fallback scan bound missing"

# Same LLC drain probes once with empty hoist plus TOCTOU cover.
grep -q "already tried group" "${DISP_HDR}" || fail "dedup prose missing"
grep -q "probes once" "${DISP_HDR}" || fail "dedup bound missing"
grep -q "next dispatch covers" "${DISP_HDR}" || fail "toctou prose missing"
grep -q "before the group lookup" "${DISP_HDR}" || fail "hoist prose missing"
grep -q "before the dedup lookup" "${DISP_HDR}" || fail "dedup hoist prose missing"
grep -q "flow_edq_empty(&flow_edqs\[victim\])" "${DISP_HDR}" || fail "empty hoist missing"

# Cluster gate stays always on with init one and no userspace seed.
grep -q "always on" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "always on prose missing"
grep -q "init one" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "always on seed missing"

# Fallback peek stays borrowed with no release.
grep -q "borrowed" "${DISP_HDR}" || fail "borrowed prose missing"
grep -q "no release" "${DISP_HDR}" || fail "borrowed release prose missing"

# Scheduler README keeps idle only with no preempt site.
grep -q "with no preempt even on" "${SRC_DIR}/README.md" || fail "readme idle only missing"

# Shared header keeps Virtual deadline in full words with no shorthand.
grep -q "Virtual deadline holds" "${SRC_DIR}/src/bpf/intf.h" || fail "intf deadline words missing"
grep -q "Virtual deadline mirrors" "${SRC_DIR}/src/bpf/intf.h" || fail "intf mirror words missing"
if grep -q "Vd holds\|Vd mirrors" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "short deadline reappeared"
fi

# Guard kept helpers stay with no new dead helper.
grep -q "flow_fb_inc" "${SRC_DIR}/src/bpf/stats.bpf.h" || fail "fb inc missing"

echo "guard tests passed"
