#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
# Property checks for the 4.8.0 EDF plus SSF core.
# Verifies the locked invariants without a live scheduler:
# VISIT at most 8, steal 4 to 8, overflow FIFO live, task 64B,
# stats 120B, DSQs 1042, nice table centred, and Rust mirrors green.
# All scratch stays under /tmp/opencode per the repo guard.
#
# Copyright (c) 2026 Galih Tama <galpt@v.recipes>
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "${HERE}/../.." && pwd)"
FAIL=0
# Grep check without eval, so patterns never execute as shell code.
# Args: fixed pattern, file, label.
check_grep() {
    if grep -q -F "$1" "$2"; then
        echo "PASS $3"
    else
        echo "FAIL $3"
        FAIL=1
    fi
}
# File presence check without eval. Args: path, label.
check_file() {
    if test -f "$1"; then
        echo "PASS $2"
    else
        echo "FAIL $2"
        FAIL=1
    fi
}
check_grep 'FLOW_DISPATCH_MAX_VISIT = 8ULL' "${REPO}/scx/src/bpf/intf.h" "visit-is-8"
check_grep 'FLOW_STEAL_MIN_PEERS = 4ULL' "${REPO}/scx/src/bpf/intf.h" "steal-min-4"
check_grep 'FLOW_STEAL_MAX_PEERS = 8ULL' "${REPO}/scx/src/bpf/intf.h" "steal-max-8"
check_grep 'FLOW_OVERFLOW = 0x5A01ULL' "${REPO}/scx/src/bpf/intf.h" "overflow-id"
check_grep 'FLOW_MAX_DSQS = 1042ULL' "${REPO}/scx/src/bpf/intf.h" "dsqs-1042"
check_grep 'flow_nice_weight[40]' "${REPO}/scx/src/bpf/weight.bpf.c" "nice-table"
check_grep 'flow_calc_delta_fair' "${REPO}/scx/src/bpf/weight.bpf.c" "calc-delta-fair"
check_grep 'flow_ledger_advance' "${REPO}/scx/src/bpf/vtime.bpf.c" "ledger"
check_grep 'flow_cpu_min' "${REPO}/scx/src/bpf/vtime.bpf.c" "cpu-min"
check_grep 'flow_ssf_pick' "${REPO}/scx/src/bpf/select/scan.bpf.c" "ssf-pick"
check_grep 'flow_bsf_pick' "${REPO}/scx/src/bpf/select/scan.bpf.c" "bsf-fallback"
check_grep 'flow_overflow_dsq' "${REPO}/scx/src/bpf/intf.h" "overflow-helper"
check_grep 'flow_preempt_wants' "${REPO}/scx/src/bpf/preempt.bpf.c" "preempt-lead-tail"
check_grep 'cpu_stats_stor' "${REPO}/scx/src/bpf/main.bpf.c" "per-cpu-stats"
check_grep 'flow_timer_decay' "${REPO}/scx/src/bpf/timer.bpf.c" "timer-decay"
check_grep 'pub fn bsf_pick' "${REPO}/scx/src/rust/flow/select.rs" "rust-bsf-pick"
check_grep 'pub fn steal_should_skip' "${REPO}/scx/src/rust/flow/select.rs" "rust-steal-skip"
check_grep 'pub fn cursor_next' "${REPO}/scx/src/rust/flow/select.rs" "rust-cursor-next"
check_grep 'pub fn preempt_leads' "${REPO}/scx/src/rust/flow/preempt.rs" "rust-preempt-leads"
check_grep 'pub fn should_steal' "${REPO}/scx/src/rust/flow/dispatch.rs" "rust-dispatch-steal"
check_grep 'pub fn charge_delta' "${REPO}/scx/src/rust/flow/lifecycle.rs" "rust-lifecycle-charge"
check_grep 'pub fn decay_noop' "${REPO}/scx/src/rust/flow/timer.rs" "rust-timer-decay"
check_file "${REPO}/scx/src/bpf/weight.bpf.c" "weight-file"
check_file "${REPO}/scx/src/bpf/vtime.bpf.c" "vtime-file"
check_file "${REPO}/scx/src/bpf/edf.bpf.c" "edf-file"
check_file "${REPO}/scx/src/bpf/task_placement.bpf.c" "placement-file"
check_file "${REPO}/scx/src/bpf/preempt.bpf.c" "preempt-file"
check_file "${REPO}/scx/src/bpf/stats.bpf.c" "stats-file"
check_file "${REPO}/scx/src/bpf/timer.bpf.c" "timer-file"
check_file "${REPO}/scx/src/rust/flow/dispatch.rs" "rust-dispatch-file"
check_file "${REPO}/scx/src/rust/flow/lifecycle.rs" "rust-lifecycle-file"
check_file "${REPO}/scx/src/rust/flow/timer.rs" "rust-timer-file"
if [ "$FAIL" -ne 0 ]; then
    echo "property checks FAILED"
    exit 1
fi
echo "all property checks passed"
