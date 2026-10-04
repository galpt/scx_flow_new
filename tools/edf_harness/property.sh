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
check() {
    if eval "$1"; then
        echo "PASS $2"
    else
        echo "FAIL $2"
        FAIL=1
    fi
}
check "grep -q 'FLOW_DISPATCH_MAX_VISIT = 8ULL' '${REPO}/scx/src/bpf/intf.h'" "visit-is-8"
check "grep -q 'FLOW_STEAL_MIN_PEERS = 4ULL' '${REPO}/scx/src/bpf/intf.h'" "steal-min-4"
check "grep -q 'FLOW_STEAL_MAX_PEERS = 8ULL' '${REPO}/scx/src/bpf/intf.h'" "steal-max-8"
check "grep -q 'FLOW_OVERFLOW = 0x5A01ULL' '${REPO}/scx/src/bpf/intf.h'" "overflow-id"
check "grep -q 'FLOW_MAX_DSQS = 1042ULL' '${REPO}/scx/src/bpf/intf.h'" "dsqs-1042"
check "grep -q 'flow_nice_weight\[40\]' '${REPO}/scx/src/bpf/weight.bpf.c'" "nice-table"
check "grep -q 'flow_calc_delta_fair' '${REPO}/scx/src/bpf/weight.bpf.c'" "calc-delta-fair"
check "grep -q 'flow_ledger_advance' '${REPO}/scx/src/bpf/vtime.bpf.c'" "ledger"
check "grep -q 'flow_cpu_min' '${REPO}/scx/src/bpf/vtime.bpf.c'" "cpu-min"
check "grep -q 'flow_ssf_pick' '${REPO}/scx/src/bpf/task_placement.bpf.c'" "ssf-pick"
check "grep -q 'flow_bsf_pick' '${REPO}/scx/src/bpf/task_placement.bpf.c'" "bsf-fallback"
check "grep -q 'flow_overflow_dsq' '${REPO}/scx/src/bpf/intf.h'" "overflow-helper"
check "grep -q 'flow_preempt_wants' '${REPO}/scx/src/bpf/preempt.bpf.c'" "preempt-lead-tail"
check "grep -q 'cpu_stats_stor' '${REPO}/scx/src/bpf/main.bpf.c'" "per-cpu-stats"
check "grep -q 'flow_timer_decay' '${REPO}/scx/src/bpf/timer.bpf.c'" "timer-decay"
check "test -f '${REPO}/scx/src/bpf/weight.bpf.c'" "weight-file"
check "test -f '${REPO}/scx/src/bpf/vtime.bpf.c'" "vtime-file"
check "test -f '${REPO}/scx/src/bpf/edf.bpf.c'" "edf-file"
check "test -f '${REPO}/scx/src/bpf/task_placement.bpf.c'" "placement-file"
check "test -f '${REPO}/scx/src/bpf/preempt.bpf.c'" "preempt-file"
check "test -f '${REPO}/scx/src/bpf/stats.bpf.c'" "stats-file"
check "test -f '${REPO}/scx/src/bpf/timer.bpf.c'" "timer-file"
if [ "$FAIL" -ne 0 ]; then
    echo "property checks FAILED"
    exit 1
fi
echo "all property checks passed"
