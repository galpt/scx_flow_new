// SPDX-License-Identifier: GPL-2.0
/*
 * Topology order for the flow scheduler.
 *
 * Online tests use plain compares with no walk. Same node tests
 * compare cached values with saturation checks at the edges.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#include <scx/common.bpf.h>
#include "topology.bpf.h"
__hidden bool flow_topo_online(u32 cpu, u64 nr_cpus)
{
	if (!flow_cpu_ok(cpu))
		return false;
	if (nr_cpus && (u64)cpu >= nr_cpus)
		return false;
	return true;
}
__hidden bool flow_topo_same_node(u32 got, u32 node)
{
	if (!flow_node_ok(got))
		return false;
	if (!flow_node_ok(node))
		return false;
	return got == node;
}
