/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Trimmed topology for the flow scheduler. Only the
 * static per cpu cards and the live frequency read are
 * needed. Placement needs no bitmaps or sibling tables.
 */
use log::warn;
use scx_utils::Topology;

/* Compile time cpu bound. Matches the BPF header. */
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

/* True when a lower id shares the core. */
fn has_older(topo: &Topology, id: usize, core: usize) -> bool {
    topo.all_cpus
        .iter()
        .any(|(oid, o)| o.core_id == core && *oid < id)
}

/*
 * Static per cpu cards seeded once at attach. Max
 * frequency, cache domain and thread role come from
 * the host topology. Failures yield an empty list so
 * the scheduler keeps running without cards.
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
            running_level: -1,
            running_pid: 0,
        });
    }
    out.sort_by_key(|e| e.id);
    out
}

/*
 * Live frequency of one cpu in kilohertz. Reads the
 * cpufreq file. Missing files yield zero.
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
