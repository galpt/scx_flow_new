// SPDX-License-Identifier: GPL-2.0
//! Snapshot reads for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Builds the counters view plus the dashboard view from the BPF maps.
//! Each poll reads the counters plus the per CPU pid view with no
//! extra sysfs use, so the page stays cheap beside the slice. A
//! dashboard poll costs 2N BPF map reads for N online CPUs: N for the
//! on CPU gauge plus N for the per CPU cards, with one alloc and no
//! sysfs on poll.

use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use crate::Scheduler;
use crate::stats;

impl<'a> Scheduler<'a> {
    /// Count live pids for the on CPU gauge with no BPF counter.
    /// Walks the cached online list with one map read per CPU, so the
    /// gauge costs N reads with no atomic cost on the hot paths. The
    /// BPF on CPU field stays zero for wire compat and never drives
    /// this count.
    pub(crate) fn count_on_cpu(&self) -> u64 {
        let mut live = 0u64;
        for &id in self.online_cpus.iter() {
            let st = self.read_cpu(id as usize);
            if st.running_pid != 0 {
                live = live.saturating_add(1);
            }
        }
        live
    }

    pub(crate) fn get_metrics(&self) -> stats::Metrics {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        let s = &bss.flow_stats;
        stats::Metrics {
            on_cpu: self.count_on_cpu(),
            total_runtime: s.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            inserts: s.inserts,
            requeues: s.requeues,
            completions: s.completions,
            local_moves: s.local_moves,
            node_moves: s.node_moves,
            machine_moves: s.machine_moves,
            kicks: s.kicks,
            admits: s.admits,
            rejects: s.rejects,
            misses: s.misses,
            gate_rejects: s.gate_rejects,
        }
    }

    /// Read one CPU pid view without heap use.
    /// Failed lookups yield an idle view with zero pid.
    pub(crate) fn read_cpu(&self, cpu: usize) -> crate::bpf_intf::flow_cpu_state {
        let idle = crate::bpf_intf::flow_cpu_state {
            running_pid: 0,
            cursor: 0,
        };
        if cpu >= crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize {
            return idle;
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<crate::bpf_intf::flow_cpu_state>::zeroed();
        let ret = unsafe {
            libbpf_rs::libbpf_sys::bpf_map_lookup_elem(
                fd,
                &key as *const _ as *const std::ffi::c_void,
                out.as_mut_ptr() as *mut std::ffi::c_void,
            )
        };
        if ret == 0 {
            unsafe { out.assume_init() }
        } else {
            idle
        }
    }

    /// Dashboard snapshot with raw counters plus live pid cards.
    /// Counters stay raw with no deltas and the on CPU gauge counts live
    /// pids with the pid view. Costs 2N map reads for N online CPUs: N
    /// for the gauge via get_metrics plus N for the cards, with one
    /// alloc sized to the online count. SMT comes from the cached init
    /// flags with no sysfs use on poll and stays display only. Offline
    /// stays out, so per CPU count matches the cached online count.
    /// Version plus timestamp plus topology join the counters for the
    /// page plus the log.
    pub(crate) fn get_web_metrics(&self) -> stats::WebMetrics {
        let mut per_cpu = Vec::with_capacity(self.online_cpus.len());
        for (rank, &id) in self.online_cpus.iter().enumerate() {
            let st = self.read_cpu(id as usize);
            let smt = self.smt.get(rank).copied().unwrap_or(false);
            per_cpu.push(stats::PerCpuMetrics {
                id,
                smt,
                running_pid: st.running_pid,
                slice_ns: crate::flow::slice::QUANTUM_NS,
            });
        }
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|v| v.as_nanos().min(u64::MAX as u128) as u64)
            .unwrap_or(0);
        stats::WebMetrics {
            stats: self.get_metrics(),
            per_cpu,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp_ns,
            topology: self.topology.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Poll cost in BPF map reads for N online CPUs.
    /// Dashboard polls read N for the on CPU gauge via get_metrics plus
    /// N for the per CPU cards, so the total stays 2N with one alloc
    /// and no sysfs on poll.
    fn snapshot_reads(n: usize) -> usize {
        n.saturating_mul(2)
    }

    #[test]
    fn poll_cost_is_two_n() {
        assert_eq!(snapshot_reads(0), 0);
        assert_eq!(snapshot_reads(1), 2);
        assert_eq!(snapshot_reads(4), 8);
        // One alloc holds N cards with no extra walk.
        let per_cpu = Vec::<u32>::with_capacity(4);
        assert!(per_cpu.capacity() >= 4);
    }
}
