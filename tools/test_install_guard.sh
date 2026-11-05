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
[ "${want}" = "5.1.4" ] || fail "version not at 5.1.4"

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
[ "$(sha256sum "${SRC_DIR}/README.md" | cut -d ' ' -f 1)" = "42e65202aa7cf7f1080cfd8ef885d8971cbc5c443e5b0f282c426fab07c9d2fd" ] || fail "scx README drifted"
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

# SJF stays non preemptive with fixed integers and no knob. The burst
# keeps half of the old value and adds half of the sample, ages down
# on long waits with a rescue on very long waits, picks one of four
# queues by remaining plus age, and wakes idle targets only with a skip
# otherwise. Remaining takes the aged estimate minus the burnt part
# with saturation at the floor. Stopping folds burnt time through
# the half blend with no wait plus remain step. No streak plus no hog
# plus no demote is kept.
SJF_HDR="${SRC_DIR}/src/bpf/sjf.bpf.h"
SJF_ENQ="${SRC_DIR}/src/bpf/enqueue.bpf.h"
grep -q "flow_sjf_next" "${SJF_HDR}" || fail "sjf blend missing"
grep -q "flow_sjf_prio" "${SJF_HDR}" || fail "sjf prio missing"
grep -q "flow_sjf_age" "${SJF_HDR}" || fail "sjf age missing"
grep -q "flow_sjf_remain" "${SJF_HDR}" || fail "sjf remain missing"
grep -q "FLOW_SJF_INIT_NS = 3000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf seed missing"
grep -q "FLOW_STARVE_NS = 200000000ULL" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf rescue missing"
grep -q ">> 1" "${SJF_HDR}" || fail "sjf half blend missing"
grep -q "FLOW_SLICE_MIN_NS \* 3" "${SJF_HDR}" || fail "sjf norm band missing"
grep -q "FLOW_AGING_NS" "${SJF_HDR}" || fail "sjf batch band missing"
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
grep -q "flow_lat_key" "${SJF_ENQ}" || fail "lat key missing"
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

# Ops stay at sixteen with no probe added.
[ "$(grep -rh "BPF_STRUCT_OPS" "${SRC_DIR}/src/bpf" | wc -l | tr -d ' ')" = "16" ] || fail "ops count drifted"

# Queues are four per LLC and fallback with kernel order and
# insertion ties. Fair scales base by share while extra stays uniform
# with a per LLC floor and a latency shift. Short jobs keep half of
# the old value and add half of the sample. Wakes go idle only with
# a skip otherwise and no gap plus tail plus escape.
grep -q "FLOW_PRIO_COUNT" "${SRC_DIR}/src/bpf/intf.h" || fail "prio count missing"
grep -q "flow_llc_dsq_prio" "${SRC_DIR}/src/bpf/intf.h" || fail "prio queue helper missing"
grep -q "FLOW_FAIR_BASE_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair base missing"
grep -q "FLOW_FAIR_EXTRA_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "fair extra missing"
grep -q "flow_fair_charge" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "fair charge missing"
grep -q "flow_seq_floor" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "floor helper missing"
grep -q "flow_lat_key" "${SRC_DIR}/src/bpf/fair.bpf.h" || fail "lat shift helper missing"
grep -q "flow_sjf_next" "${SJF_HDR}" || fail "sjf blend missing"
grep -q "FLOW_SJF_INIT_NS" "${SRC_DIR}/src/bpf/intf.h" || fail "sjf init missing"
grep -q "flow_cgroup_lookup" "${SRC_DIR}/src/bpf/cgroup.bpf.h" || fail "cgroup live lookup missing"
grep -q "gpu_hint" "${SRC_DIR}/src/bpf/intf.h" || fail "gpu hint missing"
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

echo "guard tests passed"
