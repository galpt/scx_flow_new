// SPDX-License-Identifier: GPL-2.0
//! Topology seeding for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Maps topology LLC and node ids to BPF indices.

use anyhow::Context;
use anyhow::Result;
use scx_utils::Topology;

use crate::BpfSkel;

/// Seed one CPU row per online CPU into the BPF view.
/// Maps topology LLC and node ids to contiguous indices for the
/// BPF bounds. Failures return an error.
pub fn seed_topology(skel: &mut BpfSkel<'_>) -> Result<String> {
    use libbpf_rs::MapCore;
    let topo = Topology::new().context("topology discovery")?;
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let mut node_ids: Vec<usize> = topo.nodes.keys().copied().collect();
    node_ids.sort_unstable();
    if llc_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_LLCS as usize {
        anyhow::bail!("LLC count over bound");
    }
    if node_ids.len() > crate::bpf_intf::flow_consts_FLOW_MAX_NODES as usize {
        anyhow::bail!("node count over bound");
    }
    let mut seeded = 0u32;
    let mut cpus: Vec<usize> = topo.all_cpus.keys().copied().collect();
    cpus.sort_unstable();
    for cpu in cpus {
        if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
            continue;
        }
        let entry = match topo.all_cpus.get(&cpu) {
            Some(v) => v,
            None => continue,
        };
        let llc = llc_ids.iter().position(|v| *v == entry.llc_id).unwrap_or(0) as u32;
        let node = node_ids
            .iter()
            .position(|v| *v == entry.node_id)
            .unwrap_or(0) as u32;
        let key = (cpu as u32).to_ne_bytes();
        let mut val = [0u8; 16];
        val[0..4].copy_from_slice(&(cpu as u32).to_ne_bytes());
        val[4..8].copy_from_slice(&llc.to_ne_bytes());
        val[8..12].copy_from_slice(&node.to_ne_bytes());
        skel.maps
            .cpu_ctx_stor
            .update(&key, &val, libbpf_rs::MapFlags::ANY)
            .with_context(|| format!("cpu seed failed for cpu {cpu}"))?;
        seeded += 1;
    }
    Ok(format!(
        "{} cpus {} llcs {} nodes",
        seeded,
        llc_ids.len(),
        node_ids.len()
    ))
}
