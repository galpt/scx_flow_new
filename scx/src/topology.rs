// SPDX-License-Identifier: GPL-2.0
//! Topology seeding for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Seeds cluster hints for the BPF view. Cache and node identity
//! come from the upstream topology tree built by the arena library.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::Context;
use anyhow::Result;
use scx_utils::Core;
use scx_utils::Topology;

use crate::BpfSkel;

/// Cores grouped per cluster. Fixed width keeps the seed stable.
/// Width four is a heuristic: real clusters of eight split in two,
/// which keeps locality without ever merging distant cores. The
/// topology view has no cluster id, so the seed sorts cores by id
/// within each LLC and splits every four for a stable map.
const GROUP_WIDTH: usize = 4;

/// True when any core holds more than one CPU.
pub fn smt_on(topo: &Topology) -> bool {
    topo.all_cores.values().any(|c| c.cpus.len() > 1)
}

/// Known cluster for a core or none. Minus one and 65535 are unknown.
fn core_cluster(core: &Core) -> Option<isize> {
    if core.cluster_id != -1 && core.cluster_id != 65535 {
        return Some(core.cluster_id);
    }
    for cpu in core.cpus.values() {
        if cpu.cluster_id != -1 && cpu.cluster_id != 65535 {
            return Some(cpu.cluster_id);
        }
    }
    None
}

/// Group count with unknown fallback. Minus one and 65535 count as unknown.
fn describe_topo_groups(topo: &Topology) -> usize {
    let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
    llc_ids.sort_unstable();
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    for v in cpu_ccx(topo, &llc_ids).values() {
        seen.insert(*v);
    }
    seen.len().max(1)
}

/// Shape summary for info logs.
pub fn describe_topo_summary(topo: &Topology) -> String {
    let mut packages: BTreeSet<usize> = BTreeSet::new();
    for cpu in topo.all_cpus.values() {
        packages.insert(cpu.package_id);
    }
    let groups: usize = describe_topo_groups(topo);
    format!(
        "{} cpus {} packages {} nodes {} llcs {} groups",
        topo.all_cpus.len(),
        packages.len(),
        topo.nodes.len(),
        topo.all_llcs.len(),
        groups
    )
}

/// Sched use brief for info logs. Names shape plus leverage action.
pub fn describe_sched_use(topo: &Topology) -> String {
    let groups: usize = describe_topo_groups(topo);
    let llcs: usize = topo.all_llcs.len();
    let nodes: usize = topo.nodes.len();
    let smt_text: &str = if smt_on(topo) { "on" } else { "off" };
    let group_text: &str = if groups == 1 { "group" } else { "groups" };
    let llc_text: &str = if llcs == 1 { "LLC" } else { "LLCs" };
    let node_text: &str = if nodes == 1 { "node" } else { "nodes" };
    format!(
        "Topology: SMT {}, {} {}, {} {}, {} {}. Place local first then drain group LLC node remote fallback idle only. Constrained L1>L2>L3.",
        smt_text, groups, group_text, llcs, llc_text, nodes, node_text
    )
}

/// Tree lines for debug logs. L is Topology id and P is kernel id.
pub fn render_topo_lines(topo: &Topology) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    out.push(String::from("Machine"));
    let groups: usize = describe_topo_groups(topo);
    let show_cluster: bool = groups > 1;
    let mut pkg_set: BTreeSet<usize> = BTreeSet::new();
    for cpu in topo.all_cpus.values() {
        pkg_set.insert(cpu.package_id);
    }
    let mut pkgs: Vec<usize> = pkg_set.into_iter().collect();
    pkgs.sort();
    let mut pkg_l: usize = 0;
    for pkg_p in pkgs {
        out.push(format!("  Package L{} P{}", pkg_l, pkg_p));
        pkg_l = pkg_l.wrapping_add(1);
        let mut node_ids: Vec<usize> = Vec::new();
        for (nid, node) in topo.nodes.iter() {
            let mut has: bool = false;
            for cpu in node.all_cpus.values() {
                if cpu.package_id == pkg_p {
                    has = true;
                    break;
                }
            }
            if has {
                node_ids.push(*nid);
            }
        }
        node_ids.sort();
        for nid in node_ids {
            let node = match topo.nodes.get(&nid) {
                Some(n) => n,
                None => continue,
            };
            out.push(format!("    Node L{} P{}", node.id, node.id));
            let mut llcs: Vec<usize> = Vec::new();
            for (lid, llc) in node.llcs.iter() {
                let mut has: bool = false;
                for cpu in llc.all_cpus.values() {
                    if cpu.package_id == pkg_p {
                        has = true;
                        break;
                    }
                }
                if has {
                    llcs.push(*lid);
                }
            }
            llcs.sort_by(|a, b| {
                let la = match node.llcs.get(a) {
                    Some(v) => v,
                    None => return std::cmp::Ordering::Equal,
                };
                let lb = match node.llcs.get(b) {
                    Some(v) => v,
                    None => return std::cmp::Ordering::Equal,
                };
                match la.kernel_id.cmp(&lb.kernel_id) {
                    std::cmp::Ordering::Equal => la.id.cmp(&lb.id),
                    other => other,
                }
            });
            for lid in llcs {
                let llc = match node.llcs.get(&lid) {
                    Some(v) => v,
                    None => continue,
                };
                out.push(format!("      L3 L{} P{}", llc.id, llc.kernel_id));
                let mut core_ids: Vec<usize> = Vec::new();
                for (cid, core) in llc.cores.iter() {
                    let mut has: bool = false;
                    for cpu in core.cpus.values() {
                        if cpu.package_id == pkg_p {
                            has = true;
                            break;
                        }
                    }
                    if has {
                        core_ids.push(*cid);
                    }
                }
                core_ids.sort_by(|a, b| {
                    let ca = match llc.cores.get(a) {
                        Some(v) => v,
                        None => return std::cmp::Ordering::Equal,
                    };
                    let cb = match llc.cores.get(b) {
                        Some(v) => v,
                        None => return std::cmp::Ordering::Equal,
                    };
                    match ca.kernel_id.cmp(&cb.kernel_id) {
                        std::cmp::Ordering::Equal => ca.id.cmp(&cb.id),
                        other => other,
                    }
                });
                for cid in core_ids {
                    let core = match llc.cores.get(&cid) {
                        Some(v) => v,
                        None => continue,
                    };
                    let cluster: Option<isize> = core_cluster(core);
                    let suffix: String = match cluster {
                        Some(c) if show_cluster => format!(" cluster C{c}"),
                        _ => String::new(),
                    };
                    out.push(format!(
                        "        Core+L2 L{} P{}{}",
                        core.id, core.kernel_id, suffix
                    ));
                    let mut pu_ids: Vec<usize> = core.cpus.keys().copied().collect();
                    pu_ids.sort();
                    for pu in pu_ids {
                        let cpu = match core.cpus.get(&pu) {
                            Some(v) => v,
                            None => continue,
                        };
                        out.push(format!("          PU L{} P{}", cpu.id, cpu.id));
                    }
                }
            }
        }
    }
    out
}

/// Index of a core position inside its LLC group.
fn chunk_index(pos: usize) -> usize {
    pos / GROUP_WIDTH
}

/// Map each CPU to a cluster id inside its LLC.
/// Known clusters map first in sorted order, else cores sort by id
/// within each LLC and split every four. Ids count up across LLCs
/// in LLC order. Splits stay safe and never merge distant cores.
fn cpu_ccx(topo: &Topology, llc_ids: &[usize]) -> BTreeMap<usize, u32> {
    let mut known: BTreeSet<isize> = BTreeSet::new();
    for core in topo.all_cores.values() {
        if let Some(c) = core_cluster(core) {
            known.insert(c);
        }
    }
    let mut slot: BTreeMap<isize, u32> = BTreeMap::new();
    let mut next: u32 = 0;
    for c in known {
        slot.insert(c, next);
        next = next.wrapping_add(1);
    }
    let mut core_ccx: BTreeMap<(usize, usize), u32> = BTreeMap::new();
    for (id, core) in topo.all_cores.iter() {
        let c = match core_cluster(core) {
            Some(v) => v,
            None => continue,
        };
        let idx = llc_ids.iter().position(|v| *v == core.llc_id).unwrap_or(0);
        if let Some(s) = slot.get(&c) {
            core_ccx.insert((idx, *id), *s);
        }
    }
    let mut unknown_per_llc: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (id, core) in topo.all_cores.iter() {
        if core_cluster(core).is_some() {
            continue;
        }
        let idx = llc_ids.iter().position(|v| *v == core.llc_id).unwrap_or(0);
        unknown_per_llc.entry(idx).or_default().insert(*id);
    }
    let mut ordered: Vec<usize> = unknown_per_llc.keys().copied().collect();
    ordered.sort_unstable();
    for idx in ordered {
        let cores: Vec<usize> = unknown_per_llc
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
/// Writes the CPU id plus the cluster hint; cache and node come
/// from the upstream tree. The cluster stays here as an interim
/// until it moves into the tree data pointer.
/// Failures return an error.
pub fn seed_topology(skel: &mut BpfSkel<'_>, topo: &Topology) -> Result<String> {
    use libbpf_rs::MapCore;
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
    let ccx_map = cpu_ccx(topo, &llc_ids);
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
        if !topo.all_cpus.contains_key(&cpu) {
            continue;
        }
        let ccx = ccx_map.get(&cpu).copied().unwrap_or(0);
        let key = (cpu as u32).to_ne_bytes();
        let mut val = [0u8; 16];
        val[0..4].copy_from_slice(&(cpu as u32).to_ne_bytes());
        val[4..8].copy_from_slice(&ccx.to_ne_bytes());
        val[8..12].copy_from_slice(&0u32.to_ne_bytes());
        val[12..16].copy_from_slice(&0u32.to_ne_bytes());
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
    use super::cpu_ccx;
    use super::describe_sched_use;
    use super::describe_topo_groups;
    use super::describe_topo_summary;
    use super::render_topo_lines;
    use super::smt_on;
    use scx_utils::Core;
    use scx_utils::CoreType;
    use scx_utils::Cpu;
    use scx_utils::Cpumask;
    use scx_utils::Llc;
    use scx_utils::Node;
    use scx_utils::Topology;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    #[test]
    fn chunks_split_every_four() {
        assert_eq!(chunk_index(0), 0);
        assert_eq!(chunk_index(3), 0);
        assert_eq!(chunk_index(4), 1);
        assert_eq!(chunk_index(7), 1);
        assert_eq!(chunk_index(8), 2);
    }

    fn mk_cpu(
        id: usize,
        core_id: usize,
        llc_id: usize,
        node_id: usize,
        package_id: usize,
        cluster_id: isize,
    ) -> Arc<Cpu> {
        Arc::new(Cpu {
            id,
            min_freq: 0,
            max_freq: 0,
            base_freq: 0,
            cpu_capacity: 1024,
            kernel_cpu_capacity: None,
            smt_level: 0,
            pm_qos_resume_latency_us: 0,
            trans_lat_ns: 0,
            l2_id: core_id,
            l3_id: llc_id,
            cache_size: 0,
            core_type: CoreType::Big { turbo: false },
            core_id,
            llc_id,
            node_id,
            package_id,
            cluster_id,
        })
    }

    fn mk_core(
        id: usize,
        kernel_id: usize,
        cluster_id: isize,
        cpus: BTreeMap<usize, Arc<Cpu>>,
        llc_id: usize,
        node_id: usize,
    ) -> Arc<Core> {
        Arc::new(Core {
            id,
            kernel_id,
            cluster_id,
            cpus,
            span: Cpumask::new(),
            core_type: CoreType::Big { turbo: false },
            llc_id,
            node_id,
        })
    }

    fn mk_llc(
        id: usize,
        kernel_id: usize,
        cores: BTreeMap<usize, Arc<Core>>,
        node_id: usize,
    ) -> Arc<Llc> {
        let mut all_cpus: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        for core in cores.values() {
            for (cid, cpu) in core.cpus.iter() {
                all_cpus.insert(*cid, cpu.clone());
            }
        }
        Arc::new(Llc {
            id,
            kernel_id,
            cores,
            span: Cpumask::new(),
            node_id,
            all_cpus,
        })
    }

    fn mk_node(id: usize, llcs: BTreeMap<usize, Arc<Llc>>) -> Node {
        let mut all_cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        let mut all_cpus: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        for llc in llcs.values() {
            for (cid, core) in llc.cores.iter() {
                all_cores.insert(*cid, core.clone());
                for (cpuid, cpu) in core.cpus.iter() {
                    all_cpus.insert(*cpuid, cpu.clone());
                }
            }
        }
        Node {
            id,
            distance: vec![10, 10],
            llcs,
            span: Cpumask::new(),
            all_cores,
            all_cpus,
        }
    }

    fn mk_topo(nodes: BTreeMap<usize, Node>) -> Topology {
        let mut all_llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        let mut all_cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        let mut all_cpus: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        for node in nodes.values() {
            for (lid, llc) in node.llcs.iter() {
                all_llcs.insert(*lid, llc.clone());
                for (cid, core) in llc.cores.iter() {
                    all_cores.insert(*cid, core.clone());
                    for (cpuid, cpu) in core.cpus.iter() {
                        all_cpus.insert(*cpuid, cpu.clone());
                    }
                }
            }
        }
        let mut smt = false;
        for core in all_cores.values() {
            if core.cpus.len() > 1 {
                smt = true;
                break;
            }
        }
        let mut topo = Topology::new().unwrap();
        topo.nodes = nodes;
        topo.span = Cpumask::new();
        topo.smt_enabled = smt;
        topo.all_llcs = all_llcs;
        topo.all_cores = all_cores;
        topo.all_cpus = all_cpus;
        topo
    }

    fn single_host_topo() -> Topology {
        let mut c0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c0.insert(0, mk_cpu(0, 0, 0, 0, 0, 0));
        c0.insert(1, mk_cpu(1, 0, 0, 0, 0, 0));
        let mut c1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c1.insert(2, mk_cpu(2, 1, 0, 0, 0, 1));
        c1.insert(3, mk_cpu(3, 1, 0, 0, 0, 1));
        let mut cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        cores.insert(0, mk_core(0, 0, 0, c0, 0, 0));
        cores.insert(1, mk_core(1, 1, 1, c1, 0, 0));
        let mut llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        llcs.insert(0, mk_llc(0, 0, cores, 0));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, llcs));
        mk_topo(nodes)
    }

    fn multi_package_topo() -> Topology {
        let mut a0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        a0.insert(0, mk_cpu(0, 0, 0, 0, 2, -1));
        let mut a1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        a1.insert(1, mk_cpu(1, 1, 0, 0, 2, -1));
        let mut acores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        acores.insert(0, mk_core(0, 0, -1, a0, 0, 0));
        acores.insert(1, mk_core(1, 1, -1, a1, 0, 0));
        let mut allcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        allcs.insert(0, mk_llc(0, 0, acores, 0));
        let mut b0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        b0.insert(2, mk_cpu(2, 2, 1, 1, 5, -1));
        let mut b1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        b1.insert(3, mk_cpu(3, 3, 1, 1, 5, -1));
        let mut bcores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        bcores.insert(2, mk_core(2, 2, -1, b0, 1, 1));
        bcores.insert(3, mk_core(3, 3, -1, b1, 1, 1));
        let mut blcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        blcs.insert(1, mk_llc(1, 1, bcores, 1));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, allcs));
        nodes.insert(1, mk_node(1, blcs));
        mk_topo(nodes)
    }

    fn large_topo() -> Topology {
        let mut cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        let mut cid: usize = 0;
        let mut pu: usize = 0;
        while cid < 542 {
            let mut one: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
            one.insert(pu, mk_cpu(pu, cid, 0, 0, 0, -1));
            cores.insert(cid, mk_core(cid, cid, -1, one, 0, 0));
            cid = cid.wrapping_add(1);
            pu = pu.wrapping_add(1);
        }
        let mut llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        llcs.insert(0, mk_llc(0, 0, cores, 0));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, llcs));
        mk_topo(nodes)
    }

    fn two_core_topo(first: isize, second: isize) -> Topology {
        let mut c0: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c0.insert(0, mk_cpu(0, 0, 0, 0, 0, first));
        let mut c1: BTreeMap<usize, Arc<Cpu>> = BTreeMap::new();
        c1.insert(1, mk_cpu(1, 1, 0, 0, 0, second));
        let mut cores: BTreeMap<usize, Arc<Core>> = BTreeMap::new();
        cores.insert(0, mk_core(0, 0, first, c0, 0, 0));
        cores.insert(1, mk_core(1, 1, second, c1, 0, 0));
        let mut llcs: BTreeMap<usize, Arc<Llc>> = BTreeMap::new();
        llcs.insert(0, mk_llc(0, 0, cores, 0));
        let mut nodes: BTreeMap<usize, Node> = BTreeMap::new();
        nodes.insert(0, mk_node(0, llcs));
        mk_topo(nodes)
    }

    fn seeded_groups(topo: &Topology) -> usize {
        let mut llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
        llc_ids.sort_unstable();
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        for v in cpu_ccx(topo, &llc_ids).values() {
            seen.insert(*v);
        }
        seen.len().max(1)
    }

    #[test]
    fn single_host_tree_shape() {
        let topo = single_host_topo();
        assert!(smt_on(&topo));
        let lines = render_topo_lines(&topo);
        assert_eq!(lines.len(), 10);
        assert_eq!(lines[0], String::from("Machine"));
        assert_eq!(lines[1], String::from("  Package L0 P0"));
        assert_eq!(lines[2], String::from("    Node L0 P0"));
        assert_eq!(lines[3], String::from("      L3 L0 P0"));
        assert_eq!(lines[4], String::from("        Core+L2 L0 P0 cluster C0"));
        assert_eq!(lines[5], String::from("          PU L0 P0"));
        assert_eq!(lines[6], String::from("          PU L1 P1"));
        assert_eq!(lines[7], String::from("        Core+L2 L1 P1 cluster C1"));
        assert_eq!(lines[8], String::from("          PU L2 P2"));
        assert_eq!(lines[9], String::from("          PU L3 P3"));
        let summary = describe_topo_summary(&topo);
        assert_eq!(
            summary,
            String::from("4 cpus 1 packages 1 nodes 1 llcs 2 groups")
        );
        let brief = describe_sched_use(&topo);
        assert_eq!(
            brief,
            String::from(
                "Topology: SMT on, 2 groups, 1 LLC, 1 node. Place local first then drain group LLC node remote fallback idle only. Constrained L1>L2>L3."
            )
        );
        assert!(brief.len() <= 160);
    }

    #[test]
    fn multi_package_tree_shape() {
        let topo = multi_package_topo();
        assert!(!smt_on(&topo));
        let lines = render_topo_lines(&topo);
        assert_eq!(lines.len(), 15);
        assert_eq!(lines[0], String::from("Machine"));
        assert_eq!(lines[1], String::from("  Package L0 P2"));
        assert_eq!(lines[2], String::from("    Node L0 P0"));
        assert_eq!(lines[3], String::from("      L3 L0 P0"));
        assert_eq!(lines[4], String::from("        Core+L2 L0 P0"));
        assert_eq!(lines[5], String::from("          PU L0 P0"));
        assert_eq!(lines[6], String::from("        Core+L2 L1 P1"));
        assert_eq!(lines[7], String::from("          PU L1 P1"));
        assert_eq!(lines[8], String::from("  Package L1 P5"));
        assert_eq!(lines[9], String::from("    Node L1 P1"));
        assert_eq!(lines[10], String::from("      L3 L1 P1"));
        assert_eq!(lines[11], String::from("        Core+L2 L2 P2"));
        assert_eq!(lines[12], String::from("          PU L2 P2"));
        assert_eq!(lines[13], String::from("        Core+L2 L3 P3"));
        assert_eq!(lines[14], String::from("          PU L3 P3"));
        let summary = describe_topo_summary(&topo);
        assert_eq!(
            summary,
            String::from("4 cpus 2 packages 2 nodes 2 llcs 2 groups")
        );
        let brief = describe_sched_use(&topo);
        assert!(brief.len() <= 160);
        assert!(brief.contains("SMT off"));
        assert!(
            brief.contains("2 LLCs") || brief.contains("2 groups") || brief.contains("2 nodes")
        );
    }

    #[test]
    fn truncation_counts_hidden() {
        let topo = large_topo();
        let lines = render_topo_lines(&topo);
        assert!(lines.len() > 64);
        let total = lines.len();
        assert_eq!(total, 1088);
        let hidden = total.wrapping_sub(64);
        assert_eq!(hidden, 1024);
        let marker = format!("...+{} more", hidden);
        assert_eq!(marker, String::from("...+1024 more"));
        let first: Vec<String> = lines.into_iter().take(64).collect();
        assert_eq!(first.len(), 64);
        assert_eq!(first[0], String::from("Machine"));
    }

    #[test]
    fn brief_vocab_and_len() {
        let topo = single_host_topo();
        let brief = describe_sched_use(&topo);
        assert!(brief.len() <= 160);
        assert!(brief.contains("SMT on"));
        assert!(brief.contains("groups"));
        assert!(brief.contains("LLC"));
        assert!(brief.contains("node"));
        assert!(brief.contains("Place"));
        assert!(brief.contains("local"));
        assert!(brief.contains("first"));
        assert!(brief.contains("drain"));
        assert!(brief.contains("group"));
        assert!(brief.contains("remote"));
        assert!(brief.contains("fallback"));
        assert!(brief.contains("idle"));
        assert!(brief.contains("only"));
        assert!(brief.contains("Constrained"));
        assert!(brief.contains("L1>L2>L3"));
        assert!(!brief.contains("gpu"));
        assert!(!brief.contains("cgroup"));
        assert!(!brief.contains("RED"));
        assert!(!brief.contains("mate"));
        assert!(!brief.contains("strand"));
        assert!(!brief.contains("warm"));
        assert!(!brief.contains("edf"));
        assert!(!brief.contains("lat"));
        assert!(!brief.contains("slack"));
        assert!(!brief.contains("band"));
        assert!(!brief.contains("reclaim"));
        assert!(!brief.contains("slow"));
        assert!(!brief.contains("ewma"));
        assert!(!brief.contains("dhq"));
        assert!(!brief.contains("lst"));
        assert!(!brief.contains("float"));
        assert!(!brief.contains("version"));
        assert!(!brief.contains("Vd"));
        let off = multi_package_topo();
        let off_brief = describe_sched_use(&off);
        assert!(off_brief.len() <= 160);
        assert!(off_brief.contains("SMT off"));
    }

    #[test]
    fn seed_groups_match_describe_with_known_clusters() {
        let topo = single_host_topo();
        assert_eq!(describe_topo_groups(&topo), 2);
        assert_eq!(seeded_groups(&topo), 2);
        let mixed = two_core_topo(7, -1);
        assert_eq!(describe_topo_groups(&mixed), 2);
        assert_eq!(seeded_groups(&mixed), 2);
        let lines = render_topo_lines(&mixed);
        assert_eq!(lines[4], String::from("        Core+L2 L0 P0 cluster C7"));
        assert_eq!(lines[6], String::from("        Core+L2 L1 P1"));
        let unknown = multi_package_topo();
        assert_eq!(describe_topo_groups(&unknown), 2);
        assert_eq!(seeded_groups(&unknown), 2);
    }

    #[test]
    fn unknown_sentinels_share_fallback_count() {
        for sentinel in [-1isize, 65535] {
            let topo = two_core_topo(sentinel, sentinel);
            assert_eq!(describe_topo_groups(&topo), 1);
            assert_eq!(seeded_groups(&topo), 1);
            for line in render_topo_lines(&topo) {
                assert!(!line.contains("cluster"));
            }
        }
    }
}
