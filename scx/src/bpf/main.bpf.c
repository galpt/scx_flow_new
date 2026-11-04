// SPDX-License-Identifier: GPL-2.0
/*
 * Flow scheduler BPF core.
 *
 * Thin entry with ordered includes and struct ops only. Placement
 * lives in flow headers with a lavd-style split: maps, stats,
 * guards, vtime, freq, preempt, steal, lifecycle, enqueue,
 * dispatch. Tasks enter the pair queue by vtime, else fall back
 * to the LLC DSQ. Dispatch drains pair, then LLC, then fallback
 * safety net. Single LLC bypasses pairing and uses the LLC DSQ
 * directly. Stats are per LLC with queued charged to the enqueue
 * LLC and dispatched counted on the dispatch LLC. Pair mode is
 * strict priority and picks the lowest vtime with ties going to
 * strand A. Stealing walks own pair, same node pairs, remote
 * pairs, LLC queues. Offsets 0-8 stay frozen, fallback equals
 * 4 plus 5 plus 6, steal equals 9 plus 10. No SMT probe runs
 * and each CPU stands single with fail closed choice.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include <bpf_arena_common.bpf.h>
#include <lib/arena_map.h>
#include <lib/dhq.h>
#include <lib/minheap.h>
#include <lib/sdt_alloc.h>
#include <lib/spinlock.h>
#include "intf.h"
/* The verifier ties a program to the arena on address use. */
/* Keep one use in each program that reaches arena memory. */
/* Init plus enqueue plus dispatch reach the arena, the rest use only */
/* maps and task storage and need no touch. Enqueue reaches the arena */
/* through insert, dispatch covers pop to local through the same touch. */
#define TOUCH_ARENA() do { asm volatile("" :: "r"(&arena)); } while (0)
char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);
#include "flow/maps.bpf.h"
#include "flow/stats.bpf.h"
#include "flow/guards.bpf.h"
#include "flow/vtime.bpf.h"
#include "flow/freq.bpf.h"
#include "flow/preempt.bpf.h"
#include "flow/steal.bpf.h"
#include "flow/lifecycle.bpf.h"
#include "flow/enqueue.bpf.h"
#include "flow/dispatch.bpf.h"
SCX_OPS_DEFINE(flow_ops,
	       .select_cpu		= (void *)flow_select_cpu,
	       .enqueue			= (void *)flow_enqueue,
	       .dequeue			= (void *)flow_dequeue,
	       .dispatch		= (void *)flow_dispatch,
	       .running			= (void *)flow_running,
	       .stopping		= (void *)flow_stopping,
	       .tick			= (void *)flow_tick,
	       .enable			= (void *)flow_enable,
	       .init			= (void *)flow_init,
	       .exit			= (void *)flow_exit,
	       .flags			= SCX_OPS_ENQ_LAST |
					  SCX_OPS_ENQ_EXITING |
					  SCX_OPS_ENQ_MIGRATION_DISABLED |
					  SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms		= (u32)FLOW_OPS_TIMEOUT_MS,
	       .name			= "flow");
