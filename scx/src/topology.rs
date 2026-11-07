// SPDX-License-Identifier: GPL-2.0
//! Topology seeding for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Maps topology LLC and node ids to BPF indices.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::Context;
use anyhow::Result;
use scx_utils::Topology;

use crate::BpfSkel;

/// Cores grouped per cluster. Fixed width keeps the seed stable.
const GROUP_WIDTH: usize = 4;

/// True when any core holds more than one CPU.
pub fn smt_on(topo: &Topology) -> bool {
    topo.all_cores.values().any(|c| c.cpus.len() > 1)
}

/// Detect SMT from a fresh discovery. Errors return to the caller.
pub fn detect_smt() -> Result<bool> {
    let topo = Topology::new().context("topology discovery")?;
    Ok(smt_on(&topo))
}

/// Index of a core position inside its LLC group.
fn chunk_index(pos: usize) -> usize {
    pos / GROUP_WIDTH
}

/// Map each CPU to a cluster id inside its LLC.
/// Cores sort by id within each LLC and split every four.
/// Ids count up across LLCs in LLC order.
fn cpu_ccx(topo: &Topology, llc_ids: &[usize]) -> BTreeMap<usize, u32> {
    let mut cores_per_llc: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for cpu in topo.all_cpus.values() {
        let idx = llc_ids.iter().position(|v| *v == cpu.llc_id).unwrap_or(0);
        cores_per_llc.entry(idx).or_default().insert(cpu.core_id);
    }
    let mut core_ccx: BTreeMap<(usize, usize), u32> = BTreeMap::new();
    let mut next: u32 = 0;
    let mut ordered: Vec<usize> = cores_per_llc.keys().copied().collect();
    ordered.sort_unstable();
    for idx in ordered {
        let cores: Vec<usize> = cores_per_llc
            .get(&idx)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut sorted = cores;
        sorted.sort_unstable();
        let mut last_chunk: Option<usize> = None;
        for (pos, core) in sorted.into_iter().enumerate() {
            let chunk = chunk_index(pos);
            if last_chunk != Some(chunk) {
                if pos != 0 {
                    next = next.wrapping_add(1);
                }
                last_chunk = Some(chunk);
            }
            core_ccx.insert((idx, core), next);
        }
        next = next.wrapping_add(1);
    }
    let mut out: BTreeMap<usize, u32> = BTreeMap::new();
    for (id, cpu) in topo.all_cpus.iter() {
        let idx = llc_ids.iter().position(|v| *v == cpu.llc_id).unwrap_or(0);
        if let Some(ccx) = core_ccx.get(&(idx, cpu.core_id)) {
            out.insert(*id, *ccx);
        }
    }
    out
}

/// Seed one CPU row per online CPU into the BPF view.
/// Maps topology LLC and node ids to contiguous indices for the
/// BPF bounds. Cluster ids split each LLC every four cores.
/// Failures return an error.
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
    let ccx_map = cpu_ccx(&topo, &llc_ids);
    let mut groups: BTreeSet<u32> = BTreeSet::new();
    for v in ccx_map.values() {
        groups.insert(*v);
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
        let ccx = ccx_map.get(&cpu).copied().unwrap_or(0);
        let key = (cpu as u32).to_ne_bytes();
        let mut val = [0u8; 16];
        val[0..4].copy_from_slice(&(cpu as u32).to_ne_bytes());
        val[4..8].copy_from_slice(&llc.to_ne_bytes());
        val[8..12].copy_from_slice(&node.to_ne_bytes());
        val[12..16].copy_from_slice(&ccx.to_ne_bytes());
        skel.maps
            .cpu_ctx_stor
            .update(&key, &val, libbpf_rs::MapFlags::ANY)
            .with_context(|| format!("cpu seed failed for cpu {cpu}"))?;
        seeded += 1;
    }
    Ok(format!(
        "{} cpus {} llcs {} nodes {} groups",
        seeded,
        llc_ids.len(),
        node_ids.len(),
        groups.len().max(1),
    ))
}

#[cfg(test)]
mod tests {
    use super::chunk_index;

    #[test]
    fn chunks_split_every_four() {
        assert_eq!(chunk_index(0), 0);
        assert_eq!(chunk_index(3), 0);
        assert_eq!(chunk_index(4), 1);
        assert_eq!(chunk_index(7), 1);
        assert_eq!(chunk_index(8), 2);
    }
}
