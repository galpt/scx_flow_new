/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Snapshot reads for the flow scheduler. Builds the
 * metrics view and the dashboard view from the BPF
 * maps and the static cards. Gauges only, no deltas.
 * Frequency stays display only here.
 */
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use crate::stats;
use crate::Scheduler;

impl<'a> Scheduler<'a> {
    pub(crate) fn get_metrics(&self) -> stats::Metrics {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        let s = &bss.flow_stats;
        stats::Metrics {
            on_cpu: s.on_cpu,
            total_runtime: s.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos() as u64,
            inserts: s.inserts,
            requeues: s.requeues,
            completions: s.completions,
            park_moves: s.park_moves,
            steal_moves: s.steal_moves,
            kicks: s.kicks,
            enq_no_tctx: s.enq_no_tctx,
            edf_enqueued: s.edf_enqueued,
            edf_clamped: s.edf_clamped,
            edf_ordered: s.edf_ordered,
        }
    }

    /*
     * Read one CPU state without heap use. Failed
     * lookups yield an idle view with the seed mean.
     */
    pub(crate) fn read_cpu(&self, cpu: usize) -> crate::flow_cpu_state {
        let idle = crate::flow_cpu_state {
            tq_ns: crate::flow::TQ_SEED_NS,
            sum_est: 0,
            nr: 0,
            cursor: 0,
            running_est: 0,
            running_pid: 0,
            pad: 0,
            frontier: 0,
        };
        if cpu >= crate::MAX_CPUS {
            return idle;
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<crate::flow_cpu_state>::uninit();
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

    /*
     * Dashboard snapshot. Merges the static cards with
     * live state. Gauges only, no deltas. Frequency
     * stays display only and never feeds placement
     * or division.
     */
    pub(crate) fn get_web_metrics(&mut self) -> stats::WebMetrics {
        let nr = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss missing")
            .nr_cpu_ids as usize;
        let nr = nr.min(crate::MAX_CPUS);
        let now = std::time::Instant::now();
        let old = self
            .freq_read_at
            .is_none_or(|t| now.duration_since(t).as_secs() >= 1);
        if old {
            self.cur_freq_khz.clear();
            for cpu in 0..nr {
                self.cur_freq_khz
                    .push(crate::topology::current_freq_khz(cpu as u32));
            }
            self.freq_read_at = Some(now);
        }
        let mut per_cpu = Vec::with_capacity(nr);
        for cpu in 0..nr {
            let mut e = self
                .cpu_static
                .iter()
                .find(|v| v.id == cpu as u32)
                .cloned()
                .unwrap_or_default();
            e.id = cpu as u32;
            e.cur_freq_khz = self.cur_freq_khz.get(cpu).copied().unwrap_or(0);
            let st = self.read_cpu(cpu);
            e.running_est_ns = st.running_est;
            e.running_pid = st.running_pid;
            e.tq_ns = st.tq_ns;
            e.depth = st.nr;
            per_cpu.push(e);
        }
        let stats = self.get_metrics();
        stats::WebMetrics { stats, per_cpu }
    }
}
