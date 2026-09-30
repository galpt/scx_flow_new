// SPDX-License-Identifier: GPL-2.0
/*
 * Dispatch op for the thin core.
 *
 * Executes one FIFO move from the overflow tail to local. Empty
 * queues move nothing. The daemon owns order. The core keeps progress
 * with FIFO execution.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
void BPF_STRUCT_OPS(flow_dispatch, s32 cpu,
	struct task_struct *prev)
{
	u32 moved = 0;
	(void)prev;
	if (cpu < 0)
		return;
	if (!flow_cpu_live((u32)cpu)) {
		flow_gate_reject();
		return;
	}
	if (scx_bpf_dsq_move_to_local(flow_overflow_dsq(), 0))
		moved = 1;
	if (moved)
		__sync_fetch_and_add(&flow_stats.over_moves,
		    (u64)moved);
}
