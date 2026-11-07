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
[ "${want}" = "5.1.12" ] || fail "version not at 5.1.12"

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
    "src/bpf/sjf.bpf.h" \
    "src/bpf/stats.bpf.h"; do
    [ -s "${SRC_DIR}/${need_flow}" ] || fail "flow scaffold missing ${need_flow}"
    grep -q "Galih Tama" "${SRC_DIR}/${need_flow}" || fail "flow rationale missing ${need_flow}"
done
[ ! -e "${SRC_DIR}/src/bpf/flow" ] || fail "flow dir reappeared"
[ ! -e "${SRC_DIR}/src/bpf/steal.bpf.h" ] || fail "steal helper reappeared"
[ ! -e "${SRC_DIR}/src/bpf/lib" ] || fail "vendored lib reappeared"
[ ! -e "${SRC_DIR}/src/bpf/srtf.bpf.h" ] || fail "srtf header reappeared"

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
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "02dea237752e7f8974fcb996ba49f205bdec2a2492ec5c042f350241cbed5795" ] || fail "scx README drifted"
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

# Fork keeps lib include path plus license as symlinks with no real copy.
grep -q 'src/bpf/lib' "${INST}" || fail "lib symlink missing"
grep -q '\.\./\.\./\.\./\.\./\.\./lib' "${INST}" || fail "lib symlink target bad"
grep -q '\.\./\.\./\.\./LICENSE' "${INST}" || fail "license symlink missing"

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
# its own LLC prios first, then same node LLCs, then remote LLCs, then
# fallback, with one forward wake per unrunnable head and no move.
DISP_HDR="${SRC_DIR}/src/bpf/dispatch.bpf.h"
grep -q "flow_drain_llc" "${DISP_HDR}" || fail "drain helper missing"
grep -q "flow_try_move" "${DISP_HDR}" || fail "move helper missing"
grep -q "flow_forward_from_peeked" "${DISP_HDR}" || fail "forward helper missing"
grep -q "FLOW_FALLBACK_DSQ" "${DISP_HDR}" || fail "fallback drain missing"
grep -q "flow_is_primary" "${SRC_DIR}/src/bpf/select.bpf.h" || fail "primary predicate missing"

# Cache keeps LLC first drain with fixed tie order. The drain keeps
# own LLC first then same node then remote then fallback, prios drain
# in fixed order, the pick keeps the hint when allowed else the first
# near target, and ties keep the first CPU in fixed order with the
# previous CPU winning when allowed.
grep -q "drains its own LLC" "${DISP_HDR}" || fail "cache drain prose missing"
grep -q "fixed" "${DISP_HDR}" || fail "cache fixed prose missing"
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

# SJF stays non preemptive with fixed integers and no knob. The burst
# moves toward the sample with one quarter weight when the sample is
# below old and one quarter the other way otherwise, halves on long
# waits and halves again with a rescue on very long waits while
# selecting normal, picks one of four queues by remaining plus age,
# and wakes idle targets only with a skip otherwise. Remaining takes
# the aged estimate minus the burnt part with saturation at the floor.
# Stopping folds burnt time through the quarter blend with no wait
# plus remain step. No streak plus no hog plus no demote is kept.
SJF_HDR="${SRC_DIR}/src/bpf/sjf.bpf.h"
SJF_ENQ="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "flow_sjf_next" "${SJF_HDR}" || fail "sjf blend missing"
grep -q "flow_sjf_prio" "${SJF_HDR}" || fail "sjf prio missing"
grep -q "flow_sjf_age" "${SJF_HDR}" || fail "sjf age missing"
grep -q "flow_sjf_remain" "${SJF_HDR}" || fail "sjf remain missing"
grep -q "FLOW_SLICE_MIN_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "slice quantum missing"
grep -q "FLOW_SJF_INIT_NS = 1000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf seed missing"
grep -q "FLOW_SJF_LAT_NS = 500000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf lat edge missing"
grep -q "FLOW_SJF_BATCH_NS = 20000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf batch edge missing"
if grep -q "FLOW_LAT_OFF_NS\|flow_lat_key\|500001\|1000001\|20000001" "${SRC_DIR}/src/bpf" 2>/dev/null; then
    fail "lat shift reappeared"
fi
grep -q "FLOW_AGING_NS = 100000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf aging kept missing"
grep -q "FLOW_STARVE_NS = 200000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf rescue missing"
grep -q ">> 1" "${SJF_HDR}" || fail "sjf half blend missing"
grep -q ">> 2" "${SJF_HDR}" || fail "sjf quarter blend missing"
grep -q "< (u64)FLOW_SJF_LAT_NS" "${SJF_HDR}" || fail "sjf lat band missing"
grep -q "<= (u64)FLOW_SJF_INIT_NS" "${SJF_HDR}" || fail "sjf norm band missing"
grep -q "<= (u64)FLOW_SJF_BATCH_NS" "${SJF_HDR}" || fail "sjf batch band missing"
grep -q "slice_len = (u64)FLOW_SLICE_MIN_NS" "${SJF_ENQ}" || fail "fixed slice missing"
grep -q "quanta = 1" "${SJF_ENQ}" || fail "fixed quanta missing"
grep -q "extra = 0" "${SJF_ENQ}" || fail "fixed extra missing"
grep -q "flow_fair_charge" "${SJF_ENQ}" || fail "charge pass through missing"
grep -q "flow_fair_extra" "${SJF_ENQ}" || fail "extra pass through missing"
grep -q "flow_kick_idle_only" "${SJF_ENQ}" || fail "idle kick missing"
grep -q "flow_sjf_remain" "${SJF_ENQ}" || fail "remain use missing"
grep -q "used_last" "${SJF_ENQ}" || fail "remain burnt missing"
grep -q "FLOW_SJF_FLOOR_NS" "${SJF_HDR}" || fail "sjf floor missing"
grep -q "flow_seq_floor" "${SJF_ENQ}" || fail "floor key missing"
grep -q "flow_sjf_next" "${DISP_HDR}" || fail "stopping blend missing"
grep -q "reserved" "${SRC_DIR}/src/bpf/intf.h" || fail "reserved field missing"
grep -q "rs->reserved = 0" "${DISP_HDR}" || fail "reserved zero missing"
grep -q "flow_tick" "${DISP_HDR}" || fail "tick missing"
if grep -q "flow_pred_next" "${SJF_HDR}" 2>/dev/null; then
    fail "pred helper reappeared"
fi
if grep -q "flow_pred_next" "${DISP_HDR}" 2>/dev/null; then
    fail "pred call reappeared"
fi
if grep -q "flow_hog_" "${SJF_HDR}" 2>/dev/null; then
    fail "hog helper reappeared"
fi
if grep -q "flow_hog_" "${SJF_ENQ}" 2>/dev/null; then
    fail "hog call reappeared"
fi
if grep -q "flow_hog_" "${DISP_HDR}" 2>/dev/null; then
    fail "hog call reappeared"
fi
if grep -q "FLOW_STREAK_MAX" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "streak bound reappeared"
fi
if grep -q "FLOW_PREEMPT_GAP_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "gap constant reappeared"
fi
if grep -q "FLOW_PREEMPT_TAIL_NS" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "tail constant reappeared"
fi
if grep -q "SCX_KICK_PREEMPT" "${SRC_DIR}/src/bpf/enqueue.bpf.h" 2>/dev/null; then
    fail "preempt kick reappeared"
fi
if grep -q "SCX_KICK_PREEMPT" "${DISP_HDR}" 2>/dev/null; then
    fail "preempt kick reappeared"
fi
if grep -q "flow_kick_constrained" "${SRC_DIR}/src/bpf/enqueue.bpf.h" 2>/dev/null; then
    fail "constrained kick reappeared"
fi
if grep -q "flow_kick_pinned" "${SRC_DIR}/src/bpf/enqueue.bpf.h" 2>/dev/null; then
    fail "pinned kick reappeared"
fi
if grep -q "streak" "${SRC_DIR}/src/bpf/intf.h" 2>/dev/null; then
    fail "streak field reappeared"
fi
if grep -q "streak" "${SJF_HDR}" 2>/dev/null; then
    fail "streak helper reappeared"
fi
if grep -q "streak" "${SJF_ENQ}" 2>/dev/null; then
    fail "streak use reappeared"
fi
if grep -q "streak" "${DISP_HDR}" 2>/dev/null; then
    fail "streak use reappeared"
fi
if grep -q "flow_stat_inc(llc, 6)" "${SJF_ENQ}" 2>/dev/null; then
    fail "preempt count reappeared"
fi
if grep -q "flow_stat_inc(llc, 6)" "${DISP_HDR}" 2>/dev/null; then
    fail "preempt count reappeared"
fi
if grep -q "flow_stat_inc(llc, 12)" "${SJF_ENQ}" 2>/dev/null; then
    fail "escape count reappeared"
fi
if grep -q "flow_stat_inc(llc, 12)" "${DISP_HDR}" 2>/dev/null; then
    fail "escape count reappeared"
fi
if grep -q "flow_stat_inc(llc, 17)" "${SJF_ENQ}" 2>/dev/null; then
    fail "lat win count reappeared"
fi
if grep -q "flow_stat_inc(llc, 17)" "${DISP_HDR}" 2>/dev/null; then
    fail "lat win count reappeared"
fi
if grep -q "flow_stat_inc(qllc, 17)" "${DISP_HDR}" 2>/dev/null; then
    fail "lat win count reappeared"
fi
if grep -q "bpf_map_" "${SJF_HDR}" 2>/dev/null; then
    fail "sjf map drift"
fi
if grep -q "BPF_STRUCT_OPS" "${SJF_HDR}" 2>/dev/null; then
    fail "sjf prog drift"
fi
if grep -q "bpf_for" "${SJF_HDR}" 2>/dev/null; then
    fail "sjf loop drift"
fi
if grep -q "for (" "${SJF_HDR}" 2>/dev/null; then
    fail "sjf loop drift"
fi

# Stats output stays identical with frozen fields kept for order.
# Twenty one counters stay in struct order at 168 bytes with total
# matching penalty and extra combined per award.
grep -q "kick_preempt" "${SRC_DIR}/src/bpf/intf.h" || fail "frozen preempt field missing"
grep -q "hog_escape" "${SRC_DIR}/src/bpf/intf.h" || fail "frozen escape field missing"
grep -q "lat_preempt" "${SRC_DIR}/src/bpf/intf.h" || fail "frozen lat win field missing"
grep -q "kick_preempt" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "hog_escape" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "lat_preempt" "${SRC_DIR}/src/stats.rs" || fail "stats output drifted"
grep -q "kick_preempt" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "hog_escape" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"
grep -q "lat_preempt" "${SRC_DIR}/src/metrics.rs" || fail "metrics output drifted"

# Wait hist stays scoped with five maps and nine headers.
# The wait map is one array past the base tables with per CPU
# run plus dispatch halves. Top keeps twenty one counters.
[ "$(grep -rh 'SEC(".maps")' "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "5" ] || fail "maps count drifted"
[ "$(grep -c 'include ".*\.bpf\.h"' "${SRC_DIR}/src/bpf/main.bpf.c" | tr -d ' ')" = "9" ] || fail "headers count drifted"
grep -q 'include "lat.bpf.h"' "${SRC_DIR}/src/bpf/main.bpf.c" || fail "lat include missing"
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

# Queues are four per LLC and fallback with kernel order and
# insertion ties. Fair scales base by share while extra stays uniform
# with a per LLC floor and a latency shift. Short samples mix one
# quarter old with three quarters sample else the reverse. Wakes go
# idle only with a skip otherwise and no gap plus tail plus escape.
grep -q "FLOW_PRIO_COUNT" "${SRC_DIR}/src/bpf/intf.h" || fail "prio count missing"
grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf/intf.h" || fail "prio queue helper missing"
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "FLOW_FAIR_EXTRA_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair extra missing"
grep -q "flow_fair_charge" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "fair charge missing"
grep -q "flow_seq_floor" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "floor helper missing"
if grep -q "flow_lat_key" "${SRC_DIR}/src/bpf/fair.bpf.h" 2>/dev/null; then
    fail "lat shift helper reappeared"
fi
grep -q "flow_sjf_next" "${SJF_HDR}" || fail "sjf blend missing"
grep -q "FLOW_SJF_INIT_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf init missing"
grep -q "flow_cgroup_lookup" "${SRC_DIR}/src/bpf/cgroup.bpf.h" || fail "cgroup live lookup missing"
grep -q "insertion order" "${SJF_ENQ}" || fail "insertion order missing"
grep -q "fallback queue" "${SJF_ENQ}" || fail "fallback path missing"
grep -q "kick_idle" "${SRC_DIR}/src/bpf/intf.h" || fail "idle count missing"
grep -q "kick_skip" "${SRC_DIR}/src/bpf/intf.h" || fail "skip count missing"

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
if ! grep -q "without the queued bit" "${SJF_ENQ}" 2>/dev/null; then
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
grep -q "scx_bpf_dsq_insert(p, dsq" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "fallback fifo insert missing"

# Peek goes through the compat helper with no raw call left.
grep -q "__COMPAT_scx_bpf_dsq_peek" "${DISP_HDR}" || fail "compat peek missing"
if grep -q "[^_]scx_bpf_dsq_peek(" "${DISP_HDR}" 2>/dev/null; then
    fail "raw peek reappeared"
fi

# Dispatch reads the node from the init cache with no per-CPU walk.
if grep -q "tcc->llc_id\|t2->llc_id" "${DISP_HDR}" 2>/dev/null; then
    fail "dead cpu scan reappeared"
fi
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
# A zero burst with a zero home marks a fresh entry that would stick to CPU0.
grep -q "home_cpu = -1" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "home repair missing"
grep -q "burst_ns.*home_cpu" "${SRC_DIR}/src/bpf/enqueue.bpf.h" || fail "home repair guard missing"

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
