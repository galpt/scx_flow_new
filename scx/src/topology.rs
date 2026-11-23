// SPDX-License-Identifier: GPL-2.0
//! CPU topology handling for scx_flow.
//!
//! Builds the topology tables the BPF program reads and the topology
//! lines printed at startup. With --unslice, it also splits the CPUs into
//! central domains and picks the fastest physical core of each, which
//! makes every scheduling decision for the domain.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use anyhow::Result;
use anyhow::bail;
use log::warn;
use scx_utils::Core;
use scx_utils::CoreType;
use scx_utils::Cpu;
use scx_utils::Topology;

use crate::bpf_intf;
use crate::cache::CpuCaches;

/// Cores per group when the kernel reports no cluster ids. Cores are taken
/// in id order within each LLC, so cores that are numbered close to each
/// other, and usually sit close to each other, share a group.
const GROUP_WIDTH: usize = 4;

/// True when any core runs more than one hardware thread.
pub fn smt_on(topo: &Topology) -> bool {
    topo.all_cores.values().any(|c| c.cpus.len() > 1)
}

/// Cluster id of a core. The kernel reports -1 or 65535 when it has none.
fn core_cluster(core: &Core) -> Option<isize> {
    let known = |id: isize| id != -1 && id != 65535;

    if known(core.cluster_id) {
        return Some(core.cluster_id);
    }
    core.cpus
        .values()
        .map(|cpu| cpu.cluster_id)
        .find(|id| known(*id))
}

/// Package and cluster id of a core. Cluster ids are only unique within a
/// package.
fn cluster_key(core: &Core) -> Option<(usize, isize)> {
    let package = core.cpus.values().next().map_or(0, |cpu| cpu.package_id);

    core_cluster(core).map(|cluster| (package, cluster))
}

/// Core group of every CPU. Cores with a cluster id are grouped by it and
/// the remaining cores of each LLC are split into groups of GROUP_WIDTH.
/// Group ids start at zero and have no gaps.
fn cpu_groups(topo: &Topology) -> BTreeMap<usize, u32> {
    let clusters: BTreeSet<(usize, isize)> = topo
        .all_cores
        .values()
        .filter_map(|c| cluster_key(c))
        .collect();
    let by_cluster: BTreeMap<(usize, isize), u32> = clusters.into_iter().zip(0u32..).collect();
    let mut next = by_cluster.len() as u32;
    let mut core_group: BTreeMap<usize, u32> = BTreeMap::new();
    let mut unclustered: BTreeMap<usize, Vec<usize>> = BTreeMap::new();

    for (id, core) in &topo.all_cores {
        match cluster_key(core).and_then(|c| by_cluster.get(&c)) {
            Some(group) => {
                core_group.insert(*id, *group);
            }
            None => unclustered.entry(core.llc_id).or_default().push(*id),
        }
    }
    for cores in unclustered.values() {
        for chunk in cores.chunks(GROUP_WIDTH) {
            for id in chunk {
                core_group.insert(*id, next);
            }
            next += 1;
        }
    }

    topo.all_cpus
        .iter()
        .filter_map(|(id, cpu)| core_group.get(&cpu.core_id).map(|g| (*id, *g)))
        .collect()
}

/// For every CPU of a core with several hardware threads, the next CPU of
/// that core, wrapping around to the first one.
fn cpu_siblings(topo: &Topology) -> BTreeMap<usize, u32> {
    let mut siblings = BTreeMap::new();

    for core in topo.all_cores.values() {
        let cpus: Vec<usize> = core.cpus.keys().copied().collect();
        if cpus.len() < 2 {
            continue;
        }
        for (i, cpu) in cpus.iter().enumerate() {
            siblings.insert(*cpu, cpus[(i + 1) % cpus.len()] as u32);
        }
    }
    siblings
}

fn nr_groups(groups: &BTreeMap<usize, u32>) -> usize {
    groups.values().collect::<BTreeSet<_>>().len()
}

/// Topology tables for the BPF program. LLCs are renumbered from zero in
/// the order of their ids. Cache sizes are in kibibytes, zero if unknown.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct BpfTopology {
    pub nr_llcs: u32,
    /// Zero when there are more groups than the BPF program can hold,
    /// which disables the group step of the idle CPU search.
    pub nr_groups: u32,
    pub cpu_llc: BTreeMap<usize, u32>,
    pub cpu_group: BTreeMap<usize, u32>,
    /// Another hardware thread of the same core, for CPUs that have one.
    pub cpu_sibling: BTreeMap<usize, u32>,
    pub llc_node: Vec<u32>,
    pub llc_kb: Vec<u32>,
}

impl BpfTopology {
    pub fn new(topo: &Topology, caches: &BTreeMap<usize, CpuCaches>) -> Result<Self> {
        let llc_ids: Vec<usize> = topo.all_llcs.keys().copied().collect();
        let node_ids: Vec<usize> = topo.nodes.keys().copied().collect();
        let max_llcs = bpf_intf::flow_consts_FLOW_MAX_LLCS as usize;

        if llc_ids.is_empty() {
            bail!("found no LLC");
        }
        let layout = if llc_ids.len() <= max_llcs {
            LlcLayout::Llc(llc_ids)
        } else if !node_ids.is_empty() && node_ids.len() <= max_llcs {
            warn!(
                "found {} LLCs, more than the {max_llcs} supported, so the CPUs of each \
                 NUMA node share one",
                llc_ids.len()
            );
            LlcLayout::Node(node_ids)
        } else {
            warn!(
                "found {} LLCs and {} NUMA nodes, more than the {max_llcs} supported, so all \
                 CPUs share one LLC",
                llc_ids.len(),
                node_ids.len()
            );
            LlcLayout::Single
        };
        let cpu_llc = topo
            .all_cpus
            .iter()
            .filter_map(|(id, cpu)| layout.llc_of(cpu).map(|llc| (*id, llc)))
            .collect();

        let mut cpu_group = cpu_groups(topo);
        let mut groups = nr_groups(&cpu_group);
        if groups > bpf_intf::flow_consts_FLOW_MAX_GROUPS as usize {
            cpu_group.clear();
            groups = 0;
        }

        // The cache sizes only say which LLC is the largest, which means
        // nothing once LLCs are merged.
        let (llc_node, llc_kb): (Vec<u32>, Vec<u32>) = match &layout {
            LlcLayout::Llc(_) => topo
                .all_llcs
                .values()
                .map(|llc| {
                    let kb = llc
                        .all_cpus
                        .keys()
                        .find_map(|cpu| caches.get(cpu))
                        .map_or(0, |c| c.l3_kb);
                    (llc.node_id as u32, kb)
                })
                .unzip(),
            LlcLayout::Node(nodes) => nodes.iter().map(|node| (*node as u32, 0)).unzip(),
            LlcLayout::Single => (vec![0], vec![0]),
        };

        Ok(Self {
            nr_llcs: llc_node.len() as u32,
            nr_groups: groups as u32,
            cpu_llc,
            cpu_group,
            cpu_sibling: cpu_siblings(topo),
            llc_node,
            llc_kb,
        })
    }
}

/// How CPUs are put into the LLCs of the BPF program: by their LLC, by
/// their NUMA node when there are too many LLCs, or all into one when
/// there are too many nodes as well. Llc and Node hold the sorted ids,
/// whose positions are the LLC numbers seen by the BPF program.
enum LlcLayout {
    Llc(Vec<usize>),
    Node(Vec<usize>),
    Single,
}

impl LlcLayout {
    fn llc_of(&self, cpu: &Cpu) -> Option<u32> {
        let index = |ids: &[usize], id: usize| ids.binary_search(&id).ok().map(|i| i as u32);

        match self {
            LlcLayout::Llc(ids) => index(ids, cpu.llc_id),
            LlcLayout::Node(ids) => index(ids, cpu.node_id),
            LlcLayout::Single => Some(0),
        }
    }
}

/// What tells how fast a CPU is, from the most to the least trusted, with
/// the file under /sys/devices/system/cpu/cpuN that reports it.
const PERF_SOURCES: [(&str, Option<&str>); 4] = [
    (
        "amd_pstate prefcore ranking",
        Some("cpufreq/amd_pstate_prefcore_ranking"),
    ),
    ("ACPI CPPC highest_perf", Some("acpi_cppc/highest_perf")),
    ("cpuinfo_max_freq", Some("cpufreq/cpuinfo_max_freq")),
    ("core type and capacity", None),
];

/// How fast each CPU of a core is, by every source of PERF_SOURCES.
struct CoreSpeed {
    /// The CPUs of the core in id order.
    cpus: Vec<usize>,
    /// One entry per CPU, None where a source reports nothing.
    hints: Vec<[Option<u64>; PERF_SOURCES.len()]>,
}

fn read_hint(cpu: usize, file: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/devices/system/cpu/cpu{cpu}/{file}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

fn cpu_hints(cpu: &Cpu) -> [Option<u64>; PERF_SOURCES.len()] {
    PERF_SOURCES.map(|(_, file)| match file {
        Some(file) => read_hint(cpu.id, file),
        None => {
            let big = matches!(cpu.core_type, CoreType::Big { .. });
            Some(((big as u64) << 32) | cpu.cpu_capacity as u64)
        }
    })
}

/// Index of the fastest of @cores, which must not be empty, and the source
/// that decided. The first source that reports every CPU and tells some
/// cores apart decides, and a core is as fast as its fastest CPU. Ties go
/// to the core with the lowest CPU id, and so does the choice when no
/// source tells the cores apart.
fn fastest_core(cores: &[CoreSpeed]) -> (usize, Option<usize>) {
    let lowest = |candidates: Vec<usize>| {
        candidates
            .into_iter()
            .min_by_key(|i| cores[*i].cpus.first().copied().unwrap_or(usize::MAX))
            .unwrap_or(0)
    };

    for src in 0..PERF_SOURCES.len() {
        if cores
            .iter()
            .any(|core| core.hints.iter().any(|h| h[src].is_none()))
        {
            continue;
        }
        let speeds: Vec<u64> = cores
            .iter()
            .map(|core| core.hints.iter().filter_map(|h| h[src]).max().unwrap_or(0))
            .collect();
        let best = speeds.iter().copied().max().unwrap_or(0);
        if speeds.iter().all(|s| *s == best) {
            continue;
        }
        let fastest = (0..cores.len()).filter(|i| speeds[*i] == best).collect();
        return (lowest(fastest), Some(src));
    }
    (lowest((0..cores.len()).collect()), None)
}

/// A central domain gets this many cores, by merging LLCs that are
/// smaller, so that small LLCs do not each give up a core to scheduling.
const DOMAIN_MIN_CORES: usize = 6;

/// An LLC with more cores than this is split into several domains, so that
/// one central CPU does not have to place the tasks of too many workers.
const DOMAIN_MAX_CORES: usize = 16;

/// A set of whole LLCs of one NUMA node, or a part of a large LLC, whose
/// workers one central core schedules for with --unslice.
pub struct CentralDomain {
    /// The CPUs of the domain in id order, those of the central core included.
    pub cpus: Vec<usize>,
    /// The CPUs of the central core in id order. The first one dispatches for
    /// the workers.
    pub central: Vec<usize>,
    /// What showed the central core to be the fastest of the domain, None
    /// when all its cores look equally fast.
    pub source: Option<&'static str>,
}

impl CentralDomain {
    /// The CPU that dispatches for the workers of the domain.
    pub fn cpu(&self) -> usize {
        self.central[0]
    }

    /// The CPU of the preemption timer: the second hardware thread of the
    /// central core, or the central CPU itself without SMT.
    pub fn timer_cpu(&self) -> usize {
        self.central.get(1).copied().unwrap_or(self.central[0])
    }
}

/// The cores of an LLC in core id order, and its NUMA node.
struct LlcCores {
    node: usize,
    cores: Vec<CoreSpeed>,
}

/// @cores in near equal parts of at most DOMAIN_MAX_CORES each.
fn split_llc(cores: Vec<CoreSpeed>) -> Vec<Vec<CoreSpeed>> {
    let parts = cores.len().div_ceil(DOMAIN_MAX_CORES).max(1);
    let (size, extra) = (cores.len() / parts, cores.len() % parts);
    let mut cores = cores.into_iter();

    (0..parts)
        .map(|i| cores.by_ref().take(size + usize::from(i < extra)).collect())
        .collect()
}

/// Add the cores left over at the end of a node to the last domain if it
/// is in the same node, or make them a domain of their own.
fn close_domain(domains: &mut Vec<(usize, Vec<CoreSpeed>)>, node: usize, cores: Vec<CoreSpeed>) {
    match domains.last_mut() {
        Some((last, prev)) if *last == node => prev.extend(cores),
        _ => domains.push((node, cores)),
    }
}

/// Split the cores of @llcs, which come in the order of their nodes and
/// ids, into central domains. LLCs of a node are merged in turn until they
/// have DOMAIN_MIN_CORES, and an LLC with more than DOMAIN_MAX_CORES is
/// split first. A domain needs a worker next to its central core, so one
/// with a single core joins its neighbour. Beyond FLOW_MAX_DOMAINS,
/// neighbouring domains are merged.
fn plan_domains(llcs: Vec<LlcCores>) -> Result<Vec<CentralDomain>> {
    let nr_cores: usize = llcs.iter().map(|llc| llc.cores.len()).sum();
    let max_domains = bpf_intf::flow_consts_FLOW_MAX_DOMAINS as usize;
    let mut domains: Vec<(usize, Vec<CoreSpeed>)> = Vec::new();
    let mut pending: Option<(usize, Vec<CoreSpeed>)> = None;

    if nr_cores < 2 {
        bail!(
            "--unslice needs at least 2 physical cores, one to schedule and one to run tasks, \
             but found {nr_cores}"
        );
    }
    for llc in llcs {
        for part in split_llc(llc.cores) {
            if let Some((node, cores)) = pending.take_if(|(node, _)| *node != llc.node) {
                close_domain(&mut domains, node, cores);
            }
            let (_, cores) = pending.get_or_insert_with(|| (llc.node, Vec::new()));
            cores.extend(part);
            if cores.len() >= DOMAIN_MIN_CORES {
                domains.extend(pending.take());
            }
        }
    }
    if let Some((node, cores)) = pending {
        close_domain(&mut domains, node, cores);
    }

    while let Some(i) = domains.iter().position(|(_, cores)| cores.len() < 2) {
        let (_, cores) = domains.remove(i);
        domains[i.saturating_sub(1)].1.extend(cores);
    }
    while domains.len() > max_domains {
        let mut merged = Vec::with_capacity(domains.len().div_ceil(2));
        let mut iter = domains.into_iter();
        while let Some((node, mut cores)) = iter.next() {
            if let Some((_, next)) = iter.next() {
                cores.extend(next);
            }
            merged.push((node, cores));
        }
        domains = merged;
    }

    Ok(domains
        .into_iter()
        .map(|(_, cores)| {
            let (idx, src) = fastest_core(&cores);
            let mut cpus: Vec<usize> = cores.iter().flat_map(|c| c.cpus.clone()).collect();
            cpus.sort_unstable();
            CentralDomain {
                cpus,
                central: cores[idx].cpus.clone(),
                source: src.map(|src| PERF_SOURCES[src].0),
            }
        })
        .collect())
}

/// Split the online CPUs into central domains for --unslice and pick the
/// fastest physical core of each.
pub fn pick_central_domains(topo: &Topology) -> Result<Vec<CentralDomain>> {
    let mut llcs: Vec<_> = topo.all_llcs.values().collect();
    llcs.sort_by_key(|llc| (llc.node_id, llc.id));

    plan_domains(
        llcs.into_iter()
            .map(|llc| LlcCores {
                node: llc.node_id,
                cores: llc
                    .cores
                    .values()
                    .filter(|core| !core.cpus.is_empty())
                    .map(|core| CoreSpeed {
                        cpus: core.cpus.keys().copied().collect(),
                        hints: core.cpus.values().map(|cpu| cpu_hints(cpu)).collect(),
                    })
                    .collect(),
            })
            .collect(),
    )
}

/// CPU ids as a kernel CPU list, such as 1-5,8-15.
pub fn cpu_list(cpus: &BTreeSet<usize>) -> String {
    let mut ranges: Vec<(usize, usize)> = Vec::new();

    for cpu in cpus {
        match ranges.last_mut() {
            Some((_, end)) if *end + 1 == *cpu => *end = *cpu,
            _ => ranges.push((*cpu, *cpu)),
        }
    }
    ranges
        .iter()
        .map(|(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}-{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn count(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// One line summary for the startup log.
pub fn describe_topo_summary(topo: &Topology) -> String {
    let packages: BTreeSet<usize> = topo.all_cpus.values().map(|c| c.package_id).collect();

    format!(
        "{}, {}, {}, {}, {}, SMT {}",
        count(topo.all_cpus.len(), "CPU"),
        count(packages.len(), "package"),
        count(topo.nodes.len(), "node"),
        count(topo.all_llcs.len(), "LLC"),
        count(nr_groups(&cpu_groups(topo)).max(1), "core group"),
        if smt_on(topo) { "on" } else { "off" },
    )
}

/// Size of a cache in kibibytes, as K or as M when it is a whole number of
/// mebibytes.
pub fn format_kb(kb: u32) -> String {
    if kb == 0 {
        String::from("unknown")
    } else if kb.is_multiple_of(1024) {
        format!("{}M", kb / 1024)
    } else {
        format!("{kb}K")
    }
}

fn cache_sizes(core: &Core, caches: &BTreeMap<usize, CpuCaches>) -> [String; 4] {
    match core.cpus.keys().find_map(|id| caches.get(id)) {
        Some(row) => [
            format_kb(row.l1d_kb),
            format_kb(row.l1i_kb),
            format_kb(row.l2_kb),
            format_kb(row.l3_kb),
        ],
        None => std::array::from_fn(|_| String::from("unknown")),
    }
}

/// One line per core with its CPUs, LLC, node, group and cache sizes, for
/// at most @limit cores. Also returns the number of cores.
pub fn render_per_core_lines(
    topo: &Topology,
    caches: &BTreeMap<usize, CpuCaches>,
    limit: usize,
) -> (Vec<String>, usize) {
    let groups = cpu_groups(topo);
    let lines = topo
        .all_cores
        .values()
        .take(limit)
        .map(|core| {
            let cpus: Vec<String> = core.cpus.keys().map(|id| id.to_string()).collect();
            let group = core
                .cpus
                .keys()
                .next()
                .and_then(|id| groups.get(id))
                .map_or_else(|| String::from("unknown"), |g| g.to_string());
            let [l1d, l1i, l2, l3] = cache_sizes(core, caches);

            format!(
                "Core L{} P{} cpus {} LLC {} node {} group {group} L1d {l1d} L1i {l1i} L2 {l2} L3 {l3}",
                core.id,
                core.kernel_id,
                cpus.join("+"),
                core.llc_id,
                core.node_id,
            )
        })
        .collect();

    (lines, topo.all_cores.len())
}

/// Collects up to a limit of lines and counts all of them.
struct CappedLines {
    lines: Vec<String>,
    total: usize,
    limit: usize,
}

impl CappedLines {
    fn push(&mut self, line: impl FnOnce() -> String) {
        self.total += 1;
        if self.lines.len() < self.limit {
            self.lines.push(line());
        }
    }
}

/// The topology as an indented tree, for at most @limit lines. Also returns
/// the number of lines in the whole tree. L is the scx_utils id and P the
/// kernel id.
pub fn render_topo_lines(topo: &Topology, limit: usize) -> (Vec<String>, usize) {
    let mut out = CappedLines {
        lines: Vec::new(),
        total: 0,
        limit,
    };
    let show_cluster = nr_groups(&cpu_groups(topo)) > 1;
    let packages: BTreeSet<usize> = topo.all_cpus.values().map(|c| c.package_id).collect();

    out.push(|| String::from("Machine"));
    for (pkg_l, pkg) in packages.into_iter().enumerate() {
        out.push(|| format!("  Package L{pkg_l} P{pkg}"));

        for node in topo.nodes.values() {
            if !node.all_cpus.values().any(|c| c.package_id == pkg) {
                continue;
            }
            out.push(|| format!("    Node L{} P{}", node.id, node.id));

            let mut llcs: Vec<_> = node
                .llcs
                .values()
                .filter(|llc| llc.all_cpus.values().any(|c| c.package_id == pkg))
                .collect();
            llcs.sort_by_key(|llc| (llc.kernel_id, llc.id));
            for llc in llcs {
                out.push(|| format!("      L3 L{} P{}", llc.id, llc.kernel_id));

                let mut cores: Vec<_> = llc
                    .cores
                    .values()
                    .filter(|core| core.cpus.values().any(|c| c.package_id == pkg))
                    .collect();
                cores.sort_by_key(|core| (core.kernel_id, core.id));
                for core in cores {
                    let suffix = match core_cluster(core) {
                        Some(c) if show_cluster => format!(" cluster C{c}"),
                        _ => String::new(),
                    };
                    out.push(|| {
                        format!("        Core+L2 L{} P{}{suffix}", core.id, core.kernel_id)
                    });
                    for cpu in core.cpus.keys() {
                        out.push(|| format!("          PU L{cpu} P{cpu}"));
                    }
                }
            }
        }
    }

    (out.lines, out.total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scx_utils::Cpumask;
    use scx_utils::Llc;
    use std::sync::Arc;

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

    /// A core of the given CPUs. Every CPU shares the core's LLC, node,
    /// package and cluster.
    fn mk_core(
        id: usize,
        cpus: &[usize],
        llc_id: usize,
        node_id: usize,
        package_id: usize,
        cluster_id: isize,
    ) -> Arc<Core> {
        Arc::new(Core {
            id,
            kernel_id: id,
            cluster_id,
            cpus: cpus
                .iter()
                .map(|cpu| {
                    (
                        *cpu,
                        mk_cpu(*cpu, id, llc_id, node_id, package_id, cluster_id),
                    )
                })
                .collect(),
            span: Cpumask::new(),
            core_type: CoreType::Big { turbo: false },
            llc_id,
            node_id,
        })
    }

    fn mk_llc(id: usize, cores: Vec<Arc<Core>>, node_id: usize) -> Arc<Llc> {
        Arc::new(Llc {
            id,
            kernel_id: id,
            all_cpus: cores
                .iter()
                .flat_map(|core| core.cpus.iter().map(|(k, v)| (*k, v.clone())))
                .collect(),
            cores: cores.into_iter().map(|core| (core.id, core)).collect(),
            span: Cpumask::new(),
            node_id,
        })
    }

    /// Nodes and the topology are built on top of the live ones, because
    /// optional scx_utils features can add fields a struct literal would
    /// have to name. Every field the tests rely on is overwritten.
    fn mk_topo(nodes: Vec<(usize, Vec<Arc<Llc>>)>) -> Topology {
        let live = Topology::new().expect("live topology");
        let template = live.nodes.values().next().expect("live node").clone();
        let mut topo = live;

        topo.nodes = BTreeMap::new();
        topo.all_llcs = BTreeMap::new();
        topo.all_cores = BTreeMap::new();
        topo.all_cpus = BTreeMap::new();
        for (id, llcs) in nodes {
            let mut node = template.clone();
            node.id = id;
            node.span = Cpumask::new();
            node.llcs = BTreeMap::new();
            node.all_cores = BTreeMap::new();
            node.all_cpus = BTreeMap::new();
            for llc in llcs {
                for core in llc.cores.values() {
                    node.all_cores.insert(core.id, core.clone());
                    topo.all_cores.insert(core.id, core.clone());
                }
                for (cpu_id, cpu) in &llc.all_cpus {
                    node.all_cpus.insert(*cpu_id, cpu.clone());
                    topo.all_cpus.insert(*cpu_id, cpu.clone());
                }
                node.llcs.insert(llc.id, llc.clone());
                topo.all_llcs.insert(llc.id, llc);
            }
            topo.nodes.insert(id, node);
        }
        topo.span = Cpumask::new();
        topo.smt_enabled = topo.all_cores.values().any(|c| c.cpus.len() > 1);
        topo
    }

    /// Two SMT cores in one LLC with cluster ids 0 and 1.
    fn single_host_topo() -> Topology {
        mk_topo(vec![(
            0,
            vec![mk_llc(
                0,
                vec![
                    mk_core(0, &[0, 1], 0, 0, 0, 0),
                    mk_core(1, &[2, 3], 0, 0, 0, 1),
                ],
                0,
            )],
        )])
    }

    /// Two packages, each with one node, one LLC and two cores, and no
    /// cluster ids.
    fn multi_package_topo() -> Topology {
        mk_topo(vec![
            (
                0,
                vec![mk_llc(
                    0,
                    vec![mk_core(0, &[0], 0, 0, 2, -1), mk_core(1, &[1], 0, 0, 2, -1)],
                    0,
                )],
            ),
            (
                1,
                vec![mk_llc(
                    1,
                    vec![mk_core(2, &[2], 1, 1, 5, -1), mk_core(3, &[3], 1, 1, 5, -1)],
                    1,
                )],
            ),
        ])
    }

    /// 542 single-thread cores in one LLC and no cluster ids.
    fn large_topo() -> Topology {
        let cores = (0..542).map(|id| mk_core(id, &[id], 0, 0, 0, -1)).collect();
        mk_topo(vec![(0, vec![mk_llc(0, cores, 0)])])
    }

    fn two_core_topo(first: isize, second: isize) -> Topology {
        mk_topo(vec![(
            0,
            vec![mk_llc(
                0,
                vec![
                    mk_core(0, &[0], 0, 0, 0, first),
                    mk_core(1, &[1], 0, 0, 0, second),
                ],
                0,
            )],
        )])
    }

    fn caches(cpus: &[usize], l3_kb: u32) -> BTreeMap<usize, CpuCaches> {
        cpus.iter()
            .map(|cpu| {
                let sizes = CpuCaches {
                    l1d_kb: 32,
                    l1i_kb: 32,
                    l2_kb: 512,
                    l3_kb,
                };
                (*cpu, sizes)
            })
            .collect()
    }

    #[test]
    fn groups_follow_known_clusters() {
        assert_eq!(nr_groups(&cpu_groups(&single_host_topo())), 2);

        let mixed = two_core_topo(7, -1);
        let groups = cpu_groups(&mixed);
        assert_eq!(groups.get(&0), Some(&0));
        assert_eq!(groups.get(&1), Some(&1));

        for unknown in [-1isize, 65535] {
            assert_eq!(nr_groups(&cpu_groups(&two_core_topo(unknown, unknown))), 1);
        }
    }

    #[test]
    fn clusters_are_per_package() {
        let topo = mk_topo(vec![
            (
                0,
                vec![mk_llc(
                    0,
                    vec![mk_core(0, &[0], 0, 0, 0, 0), mk_core(1, &[1], 0, 0, 0, 1)],
                    0,
                )],
            ),
            (
                1,
                vec![mk_llc(
                    1,
                    vec![mk_core(2, &[2], 1, 1, 1, 0), mk_core(3, &[3], 1, 1, 1, 1)],
                    1,
                )],
            ),
        ]);
        assert_eq!(nr_groups(&cpu_groups(&topo)), 4);
    }

    /// @nr_llcs single-CPU LLCs spread round robin over @nr_nodes nodes.
    fn many_llc_topo(nr_llcs: usize, nr_nodes: usize) -> Topology {
        mk_topo(
            (0..nr_nodes)
                .map(|node| {
                    let llcs = (node..nr_llcs)
                        .step_by(nr_nodes)
                        .map(|id| mk_llc(id, vec![mk_core(id, &[id], id, node, 0, -1)], node))
                        .collect();
                    (node, llcs)
                })
                .collect(),
        )
    }

    #[test]
    fn too_many_llcs_fall_back() {
        let per_node = BpfTopology::new(&many_llc_topo(100, 2), &BTreeMap::new()).unwrap();
        assert_eq!(per_node.nr_llcs, 2);
        assert_eq!(per_node.llc_node, vec![0, 1]);
        assert_eq!(per_node.cpu_llc.get(&3), Some(&1));

        let single = BpfTopology::new(&many_llc_topo(100, 100), &BTreeMap::new()).unwrap();
        assert_eq!(single.nr_llcs, 1);
        assert_eq!(single.llc_kb, vec![0]);
        assert!(single.cpu_llc.values().all(|llc| *llc == 0));
    }

    #[test]
    fn unclustered_cores_split_per_llc() {
        let groups = cpu_groups(&multi_package_topo());
        assert_eq!(groups.get(&1), Some(&0));
        assert_eq!(groups.get(&2), Some(&1));

        let large = cpu_groups(&large_topo());
        assert_eq!(large.get(&3), Some(&0));
        assert_eq!(large.get(&4), Some(&1));
        assert_eq!(nr_groups(&large), 542usize.div_ceil(GROUP_WIDTH));
    }

    #[test]
    fn bpf_tables_renumber_llcs() {
        let mut sizes = caches(&[0, 1], 98304);
        sizes.extend(caches(&[2, 3], 32768));
        let tables = BpfTopology::new(&multi_package_topo(), &sizes).unwrap();
        assert_eq!(tables.nr_llcs, 2);
        assert_eq!(tables.llc_kb, vec![98304, 32768]);
        assert_eq!(tables.nr_groups, 2);
        assert_eq!(tables.llc_node, vec![0, 1]);
        assert_eq!(
            tables.cpu_llc,
            BTreeMap::from([(0, 0), (1, 0), (2, 1), (3, 1)])
        );
        assert_eq!(
            tables.cpu_group,
            BTreeMap::from([(0, 0), (1, 0), (2, 1), (3, 1)])
        );
    }

    #[test]
    fn bpf_tables_drop_groups_over_the_limit() {
        let tables = BpfTopology::new(&large_topo(), &BTreeMap::new()).unwrap();
        assert_eq!(tables.nr_llcs, 1);
        assert_eq!(tables.nr_groups, 0);
        assert!(tables.cpu_group.is_empty());
        assert_eq!(tables.cpu_llc.len(), 542);
        assert_eq!(tables.llc_kb, vec![0]);
    }

    #[test]
    fn summary_names_the_shape() {
        assert_eq!(
            describe_topo_summary(&single_host_topo()),
            "4 CPUs, 1 package, 1 node, 1 LLC, 2 core groups, SMT on"
        );
        assert_eq!(
            describe_topo_summary(&multi_package_topo()),
            "4 CPUs, 2 packages, 2 nodes, 2 LLCs, 2 core groups, SMT off"
        );
    }

    #[test]
    fn tree_lists_every_level() {
        let (lines, total) = render_topo_lines(&single_host_topo(), usize::MAX);
        assert_eq!(total, 10);
        assert_eq!(
            lines,
            vec![
                "Machine",
                "  Package L0 P0",
                "    Node L0 P0",
                "      L3 L0 P0",
                "        Core+L2 L0 P0 cluster C0",
                "          PU L0 P0",
                "          PU L1 P1",
                "        Core+L2 L1 P1 cluster C1",
                "          PU L2 P2",
                "          PU L3 P3",
            ]
        );

        let (lines, _) = render_topo_lines(&multi_package_topo(), usize::MAX);
        assert_eq!(lines[1], "  Package L0 P2");
        assert_eq!(lines[8], "  Package L1 P5");
        assert_eq!(lines[10], "      L3 L1 P1");
        assert!(lines.iter().all(|l| !l.contains("cluster")));
    }

    #[test]
    fn tree_cluster_suffix_needs_a_known_id() {
        let (lines, _) = render_topo_lines(&two_core_topo(7, -1), usize::MAX);
        assert_eq!(lines[4], "        Core+L2 L0 P0 cluster C7");
        assert_eq!(lines[6], "        Core+L2 L1 P1");
    }

    #[test]
    fn tree_is_capped() {
        let topo = large_topo();
        let (full, total) = render_topo_lines(&topo, usize::MAX);
        assert_eq!(total, 1088);
        assert_eq!(full.len(), 1088);

        for limit in [0, 1, 64] {
            let (capped, total) = render_topo_lines(&topo, limit);
            assert_eq!(total, 1088);
            assert_eq!(capped, full[..limit]);
        }
    }

    #[test]
    fn per_core_lines_show_cache_sizes() {
        let topo = single_host_topo();
        let (lines, total) =
            render_per_core_lines(&topo, &caches(&[0, 1, 2, 3], 16384), usize::MAX);
        assert_eq!(total, 2);
        assert_eq!(
            lines[0],
            "Core L0 P0 cpus 0+1 LLC 0 node 0 group 0 L1d 32K L1i 32K L2 512K L3 16M"
        );

        let (missing, _) = render_per_core_lines(&topo, &BTreeMap::new(), usize::MAX);
        assert!(missing[0].ends_with("L1d unknown L1i unknown L2 unknown L3 unknown"));
    }

    #[test]
    fn per_core_lines_are_capped() {
        let topo = large_topo();
        for limit in [0, 1, 64, 1000] {
            let (lines, total) = render_per_core_lines(&topo, &BTreeMap::new(), limit);
            assert_eq!(total, 542);
            assert_eq!(lines.len(), limit.min(542));
        }
    }

    fn speed(cpus: &[usize], hints: &[[Option<u64>; 4]]) -> CoreSpeed {
        CoreSpeed {
            cpus: cpus.to_vec(),
            hints: hints.to_vec(),
        }
    }

    /// The only domain planned for one LLC of @cores.
    fn plan_one(cores: Vec<CoreSpeed>) -> CentralDomain {
        let mut domains = plan_domains(vec![LlcCores { node: 0, cores }]).unwrap();
        assert_eq!(domains.len(), 1);
        domains.remove(0)
    }

    #[test]
    fn fastest_core_follows_the_ranking() {
        let rank = |r: u64| [Some(r), Some(186), Some(4787082), Some(1024)];
        let cores = (0..8)
            .map(|core| {
                let r = if core == 3 || core == 5 { 196 } else { 186 };
                speed(&[2 * core, 2 * core + 1], &[rank(r), rank(r)])
            })
            .collect();
        let domain = plan_one(cores);
        assert_eq!(domain.central, vec![6, 7]);
        assert_eq!(domain.source, Some("amd_pstate prefcore ranking"));
        assert_eq!((domain.cpu(), domain.timer_cpu()), (6, 7));
        assert_eq!(domain.cpus, (0..16).collect::<Vec<_>>());
    }

    #[test]
    fn fastest_core_skips_flat_and_partial_sources() {
        let cores = vec![
            speed(&[0], &[[None, Some(5), Some(3000), Some(1024)]]),
            speed(&[1], &[[Some(9), Some(5), Some(3500), Some(1024)]]),
        ];
        let domain = plan_one(cores);
        assert_eq!(domain.central, vec![1]);
        assert_eq!(domain.source, Some("cpuinfo_max_freq"));
        assert_eq!(domain.timer_cpu(), 1);

        let big = [None, None, None, Some((1 << 32) | 1024)];
        let little = [None, None, None, Some(512)];
        let cores = vec![speed(&[0], &[little]), speed(&[4, 5], &[big, big])];
        assert_eq!(plan_one(cores).central, vec![4, 5]);
    }

    #[test]
    fn fastest_core_falls_back_to_the_lowest_cpu() {
        let same = [None, None, Some(3000), Some(1024)];
        let cores = vec![speed(&[2, 3], &[same, same]), speed(&[0, 1], &[same, same])];
        let domain = plan_one(cores);
        assert_eq!(domain.central, vec![0, 1]);
        assert_eq!(domain.source, None);
    }

    /// LLCs of equally fast SMT cores, given as (node, cores) in order.
    /// Cores and CPUs are numbered on from one LLC to the next.
    fn llcs(shape: &[(usize, usize)]) -> Vec<LlcCores> {
        let same = [None, None, Some(3000), Some(1024)];
        let mut next = 0;

        shape
            .iter()
            .map(|(node, nr_cores)| {
                let cores = (next..next + nr_cores)
                    .map(|core| speed(&[2 * core, 2 * core + 1], &[same, same]))
                    .collect();
                next += nr_cores;
                LlcCores { node: *node, cores }
            })
            .collect()
    }

    /// Cores per domain planned for @shape.
    fn domain_sizes(shape: &[(usize, usize)]) -> Vec<usize> {
        plan_domains(llcs(shape))
            .unwrap()
            .iter()
            .map(|domain| domain.cpus.len() / 2)
            .collect()
    }

    #[test]
    fn domains_merge_small_llcs() {
        assert_eq!(domain_sizes(&[(0, 8)]), vec![8]);
        assert_eq!(domain_sizes(&[(0, 8), (0, 8)]), vec![8, 8]);
        assert_eq!(domain_sizes(&[(0, 8), (1, 8)]), vec![8, 8]);
        assert_eq!(domain_sizes(&[(0, 6), (0, 6)]), vec![6, 6]);
        assert_eq!(domain_sizes(&[(0, 4); 4]), vec![8, 8]);
        assert_eq!(domain_sizes(&[(0, 3); 4]), vec![6, 6]);
        assert_eq!(domain_sizes(&[(0, 4); 3]), vec![12]);
        assert_eq!(domain_sizes(&[(0, 2)]), vec![2]);
    }

    #[test]
    fn domains_split_large_llcs() {
        assert_eq!(domain_sizes(&[(0, 32)]), vec![16, 16]);
        assert_eq!(domain_sizes(&[(0, 60)]), vec![15; 4]);
        assert_eq!(domain_sizes(&[(0, 17)]), vec![9, 8]);
        assert_eq!(domain_sizes(&[(0, 16)]), vec![16]);
    }

    #[test]
    fn domains_follow_nodes() {
        assert_eq!(domain_sizes(&[(0, 4), (1, 4)]), vec![4, 4]);
        assert_eq!(domain_sizes(&[(0, 8), (0, 2), (1, 8)]), vec![10, 8]);
        assert_eq!(domain_sizes(&[(0, 1), (1, 8)]), vec![9]);
        assert_eq!(domain_sizes(&[(0, 8), (1, 1)]), vec![9]);
    }

    #[test]
    fn domains_are_capped() {
        let max = bpf_intf::flow_consts_FLOW_MAX_DOMAINS as usize;
        let sizes = domain_sizes(&vec![(0, 6); max + 2]);
        assert_eq!(sizes.len(), max.div_ceil(2) + 1);
        assert_eq!(sizes.iter().sum::<usize>(), 6 * (max + 2));
    }

    #[test]
    fn each_domain_has_its_own_central_core() {
        let domains = plan_domains(llcs(&[(0, 4), (1, 4)])).unwrap();
        assert_eq!(domains[0].cpus, (0..8).collect::<Vec<_>>());
        assert_eq!(domains[1].cpus, (8..16).collect::<Vec<_>>());
        assert_eq!((domains[0].cpu(), domains[0].timer_cpu()), (0, 1));
        assert_eq!((domains[1].cpu(), domains[1].timer_cpu()), (8, 9));
    }

    #[test]
    fn central_domains_need_two_cores() {
        assert!(plan_domains(llcs(&[(0, 1)])).is_err());
        assert!(plan_domains(Vec::new()).is_err());
        assert_eq!(pick_central_domains(&single_host_topo()).unwrap().len(), 1);
        assert_eq!(
            pick_central_domains(&multi_package_topo()).unwrap().len(),
            2
        );
    }

    #[test]
    fn cpu_lists_use_ranges() {
        assert_eq!(
            cpu_list(&BTreeSet::from([1, 2, 3, 4, 5, 8, 9, 15])),
            "1-5,8-9,15"
        );
        assert_eq!(cpu_list(&BTreeSet::from([7])), "7");
        assert_eq!(cpu_list(&BTreeSet::new()), "");
    }

    #[test]
    fn cache_sizes_use_k_and_m() {
        assert_eq!(format_kb(0), "unknown");
        assert_eq!(format_kb(48), "48K");
        assert_eq!(format_kb(1536), "1536K");
        assert_eq!(format_kb(1024), "1M");
        assert_eq!(format_kb(98304), "96M");
    }
}
