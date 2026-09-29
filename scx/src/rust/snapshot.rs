// SPDX-License-Identifier: GPL-2.0
//! Snapshot reads for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Builds the counters view from the BPF maps with no bulk path.
//! Bulk snapshots stay disabled, so each poll reads the counters only.

use crate::Scheduler;
use crate::stats;

impl<'a> Scheduler<'a> {
    pub(crate) fn get_metrics(&self) -> stats::Metrics {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        let s = &bss.flow_stats;
        stats::Metrics {
            on_cpu: s.on_cpu,
            total_runtime: s.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            inserts: s.inserts,
            requeues: s.requeues,
            completions: s.completions,
            local_moves: s.local_moves,
            node_moves: s.node_moves,
            machine_moves: s.machine_moves,
            over_moves: s.over_moves,
            global_moves: s.global_moves,
            kicks: s.kicks,
            admits: s.admits,
            rejects: s.rejects,
            misses: s.misses,
            parks: s.parks,
            gate_rejects: s.gate_rejects,
        }
    }
}
