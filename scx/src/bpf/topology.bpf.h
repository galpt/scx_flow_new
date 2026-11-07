// SPDX-License-Identifier: GPL-2.0
/*
 * Topology order for the flow scheduler.
 *
 * Steal order stays local first then same node then remote. Online
 * checks keep the scan within the live range. Node compares test
 * cached values with no walk.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */
#ifndef __FLOW_TOPOLOGY_BPF_H
#define __FLOW_TOPOLOGY_BPF_H
#include "intf.h"
bool flow_topo_online(u32 cpu, u64 nr_cpus);
bool flow_topo_same_node(u32 got, u32 node);
#endif
