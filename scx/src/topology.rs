/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Trimmed topology for the flow scheduler. Only the
 * static per CPU cards and the live frequency read are
 * needed. Frequency plus LLC plus CPU cards stay display
 * only and never shape placement with no table in BPF.
 * Zero means unknown and keeps a plain fallback.
 */
use log::warn;
use scx_utils::Topology;

/* Compile time CPU bound. Matches the BPF header. */
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

/* True when a lower id shares the core. */
fn has_older(topo: &Topology, id: usize, core: usize) -> bool {
    topo.all_cpus
        .iter()
        .any(|(oid, o)| o.core_id == core && *oid < id)
}

/*
 * Static per CPU cards seeded once at attach. Max
 * frequency, cache domain and thread role come from
 * the host topology. Zero frequency means unknown and
 * stays display only. Failures yield an empty list so
 * the scheduler keeps running without cards. Single
 * CPU and no sibling hosts keep plain per CPU cards.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement with no table in BPF.
 */
pub fn web_cpu_static() -> Vec<crate::stats::PerCpuMetrics> {
    let topo = match Topology::new() {
        Ok(v) => v,
        Err(e) => {
            warn!("topology failed, web cards empty: {e}");
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for (id, cpu) in topo.all_cpus.iter() {
        if *id >= MAX_CPUS {
            continue;
        }
        let smt = has_older(&topo, *id, cpu.core_id);
        out.push(crate::stats::PerCpuMetrics {
            id: *id as u32,
            freq_khz: cpu.max_freq as u64,
            cur_freq_khz: 0,
            llc_id: cpu.llc_id as u32,
            smt,
            running_est_ns: 0,
            running_pid: 0,
            tq_ns: crate::flow::SLICE_NS,
            depth: 0,
        });
    }
    out.sort_by_key(|e| e.id);
    out
}

/*
 * One line topology summary for the start log. Counts
 * CPUs and notes sibling and frequency state in plain
 * words. Unknown frequency stays unknown and never
 * prints as zero. Missing cards stay unknown. Single
 * CPU prints as one CPU with no peers. No sibling
 * prints as no SMT with plain per CPU behavior.
 * Frequency plus LLC plus CPU cards stay display only
 * and never shape placement with no table in BPF.
 */
pub fn describe_topology(cards: &[crate::stats::PerCpuMetrics]) -> String {
    if cards.is_empty() {
        return "topology unknown, plain per-CPU".to_string();
    }
    let count = cards.len();
    let smt = cards.iter().any(|c| c.smt);
    let freq = cards.iter().any(|c| c.freq_khz != 0);
    let cpu_word = if count == 1 { "CPU" } else { "CPUs" };
    let smt_word = if smt { "SMT" } else { "no SMT" };
    let freq_word = if freq { "freq known" } else { "freq unknown" };
    format!(
        "topology: {} {}, {}, {}",
        count, cpu_word, smt_word, freq_word
    )
}

/*
 * Live frequency of one CPU in kilohertz. Reads the
 * cpufreq file. Missing files yield zero for unknown.
 * The value is display only and never feeds placement
 * or division. Frequency stays display only with no
 * table in BPF.
 */
pub fn current_freq_khz(cpu: u32) -> u64 {
    std::fs::read_to_string(format!(
        "{}{}{}{}",
        "/sys/devices/system/cpu/cpu", cpu, "/cpufreq/", "scaling_cur_freq"
    ))
    .ok()
    .and_then(|s| s.trim().parse().ok())
    .unwrap_or(0)
}
