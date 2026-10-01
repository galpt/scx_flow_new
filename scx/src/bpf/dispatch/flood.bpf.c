// SPDX-License-Identifier: GPL-2.0
/*
 * Flood gate for the ordered dispatch fill.
 *
 * Holds the past one hundred twenty eight queued check with four
 * ordered moves as the bound. Past deep backlog ordered stops and
 * FIFO covers the remainder to sixteen, so one pass never burns
 * sixteen double scans on a deep tail while still draining sixteen
 * with ordered first. Pure scalar check with no map use, so the
 * verifier stays small. Runs noinline with scalar moved plus queue
 * length so the ordered loop pays one call with no unrolled branch
 * tree.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
/* Flood stop with moved plus queue length solely. */
/* Gives true past one hundred twenty eight queued once four ordered */
/* moves land, so deep backlog stops ordered with FIFO covering the */
/* remainder below. Pure check with no map use. */
static __noinline bool flow_flood_stop(u32 moved, u64 qlen)
{
	if ((u64)moved < (u64)FLOW_DISPATCH_FLOOD_PROBES)
		return false;
	return qlen > (u64)FLOW_DISPATCH_FLOOD_QUEUED;
}
