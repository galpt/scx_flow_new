// SPDX-License-Identifier: GPL-2.0
//! Flow scheduler front end.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Loads the BPF object, wires stats and the dashboard, then drives the loop.

mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
#[path = "rust/config.rs"]
mod config;
#[path = "rust/flow.rs"]
mod flow;
#[path = "rust/flow_cgrp.rs"]
mod flow_cgrp;
#[path = "rust/flow_edf.rs"]
mod flow_edf;
#[path = "rust/flow_preempt.rs"]
mod flow_preempt;
#[path = "rust/flow_select.rs"]
mod flow_select;
#[path = "rust/flow_ssf.rs"]
mod flow_ssf;
#[path = "rust/flow_tree.rs"]
mod flow_tree;
#[path = "rust/flow_vruntime.rs"]
mod flow_vruntime;
#[path = "rust/rapl.rs"]
mod rapl;
#[path = "rust/snapshot.rs"]
mod snapshot;
#[path = "rust/stats.rs"]
mod stats;
#[path = "rust/topology.rs"]
mod topology;
#[path = "rust/webui.rs"]
mod webui;

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::Shell;
use clap_complete::generate;
use crossbeam::channel::RecvTimeoutError;
use log::info;
use scx_stats::prelude::*;
use scx_utils::UserExitInfo;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use config::Config;
use stats::Metrics;

/* Binary name used in logs and stats. */
const SCHEDULER_NAME: &str = "scx_flow";
/* CPU bound shared with the BPF header. */
const MAX_CPUS: usize = crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize;

fn full_version() -> String {
    build_id::full_version(env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
struct Opts {
    /* Poll interval for the stats printer. */
    #[clap(long)]
    stats: Option<f64>,
    /* Run the stats printer only. */
    #[clap(long)]
    monitor: Option<f64>,
    /* Verbose BPF logging. */
    #[clap(short = 'd', long, action = clap::ArgAction::SetTrue)]
    debug: bool,
    /* Verbose output with libbpf detail. */
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
    /* Exit dump buffer length in bytes. */
    #[clap(long, default_value = "1048576")]
    exit_dump_len: u32,
    /* Print version and exit. */
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    version: bool,
    /* Show stat descriptions. */
    #[clap(long)]
    help_stats: bool,
    /* Generate shell completions and exit. */
    #[clap(long, value_name = "SHELL", hide = true)]
    completions: Option<Shell>,
    /* Disable the loopback dashboard thread. */
    #[clap(long = "no-webui", action = clap::ArgAction::SetTrue)]
    no_webui: bool,
    #[clap(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

/*
 * Scheduler owns the skeleton, the link, the stats
 * server and the dashboard channel. It drives the run
 * loop until shutdown or exit.
 */
pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    /* Dashboard sender. None when disabled. */
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
    /* Static per-CPU cards seeded at attach. */
    cpu_static: Vec<stats::PerCpuMetrics>,
    /* Online ids once at init in rank order. */
    online_cpus: Vec<u32>,
    /* Live frequency cache by online rank. */
    cur_freq_khz: Vec<u64>,
    freq_read_at: Option<std::time::Instant>,
    started_at: std::time::Instant,
    /* Governor display with EPP and platform suffix. */
    governor: String,
    /* Last governor poll for the 1s tick writer. */
    governor_read_at: Option<std::time::Instant>,
    /* Package energy reader. None parks the probe. */
    rapl: Option<crate::rapl::RaplReader>,
    /* Strict only probe over package joules on the 1s tick. */
    probe: crate::snapshot::EnergyProbe,
    /* Latest energy view for the dashboard. */
    energy: crate::stats::EnergyMetrics,
    /* Last RAPL sample for the 1s tick cadence. */
    rapl_read_at: Option<std::time::Instant>,
}

impl<'a> Scheduler<'a> {
    fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();
        let mut bld = BpfSkelBuilder::default();
        bld.obj_builder.debug(opts.debug || opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(bld, open_object, flow_ops, open_opts)?;
        /* Validate the constants before load. */
        let cfg = Config::default();
        cfg.validate()?;
        info!("Config: {}", cfg.describe());
        /* Ops flags live in the BPF object for kernel 7.2 and up. */
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        /* Static cards seed the start log and the cards. Live frequency */
        /* stays display only and never shapes placement. */
        let cards = topology::web_cpu_static();
        /* Online ids once at init in rank order. Snapshot reads online CPUs */
        /* again each tick for hotplug. */
        let mut online = topology::online_cpus();
        if online.is_empty() {
            online = cards.iter().map(|c| c.id).collect();
            online.sort_unstable();
            online.dedup();
        }
        let mut possible = topology::possible_nr();
        if possible == 0 {
            possible = online
                .iter()
                .max()
                .map(|m| *m as usize + 1)
                .unwrap_or(0)
                .min(MAX_CPUS);
        }
        /* Governor poll once at init over online only for display. */
        let governors = topology::collect_governors(&online);
        let governor = topology::display_governor(&governors);
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        let _ = &mut skel;
        /* Seed the BPF topology view with sibling plus domain rows. */
        /* Failures keep the BPF defaults with hint order placement. */
        Self::seed_topo(&mut skel);
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        /* Bounded dashboard channel drops a frame when full. */
        let webui_tx = if opts.no_webui {
            None
        } else {
            let (tx, rx) = crossbeam::channel::bounded::<stats::WebMetrics>(16);
            let sd = shutdown.clone();
            std::thread::spawn(move || {
                webui::start(rx, sd);
            });
            Some(tx)
        };
        /* Static cards seed the start log and the cards. */
        /* Frequency stays display only here. */
        info!("Topology: {}", topology::describe_topology(&cards));
        info!("online: {} cpus over possible {}", online.len(), possible,);
        info!("governor: {}", governor);
        let rapl = crate::rapl::RaplReader::open_default();
        if rapl.is_some() {
            info!("RAPL package zone open for the energy probe");
        } else {
            log::warn!("RAPL unavailable, energy probe parked");
        }
        let cpu_static = if opts.no_webui { Vec::new() } else { cards };
        let freq_cap = online.len().min(MAX_CPUS);
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            webui_tx,
            cpu_static,
            online_cpus: online,
            cur_freq_khz: Vec::with_capacity(freq_cap),
            freq_read_at: None,
            started_at: std::time::Instant::now(),
            governor,
            governor_read_at: None,
            rapl,
            probe: crate::snapshot::EnergyProbe::new(),
            energy: crate::stats::EnergyMetrics::default(),
            rapl_read_at: None,
        })
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /* Seed one topology row per CPU into the BPF view. */
    /* Each row carries the thread sibling and the cache domain. */
    /* A failed update keeps the BPF default with no trap. */
    fn seed_topo(skel: &mut BpfSkel<'_>) {
        use libbpf_rs::MapCore;
        for (cpu, sib, llc) in topology::topo_rows() {
            let key = cpu.to_ne_bytes();
            let mut val = [0u8; 8];
            val[0..4].copy_from_slice(&sib.to_ne_bytes());
            val[4..8].copy_from_slice(&llc.to_ne_bytes());
            if let Err(e) = skel
                .maps
                .topo_stor
                .update(&key, &val, libbpf_rs::MapFlags::ANY)
            {
                log::warn!("topo seed failed for cpu {cpu}: {e}");
            }
        }
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => {
                    let web = self.get_web_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(web);
                    }
                    res_ch.send(self.get_metrics())?
                }
                Err(RecvTimeoutError::Timeout) => {
                    let web = self.get_web_metrics();
                    if let Some(ref tx) = self.webui_tx {
                        let _ = tx.try_send(web);
                    }
                }
                Err(e) => Err(e)?,
            }
        }
        let m = self.get_metrics();
        let (runtime, oncpu) = (m.total_runtime, m.on_cpu);
        info!(
            "exit ins={} req={} done={} park={} tree={} \
            kick={} noctx={} \
            pkick={} pskip={} \
            global={} \
            nthr={} parked={} bw={} cpuperf={} \
            runtime={} oncpu={}",
            m.inserts,
            m.requeues,
            m.completions,
            m.park_moves,
            m.tree_moves,
            m.kicks,
            m.enq_no_tctx,
            m.preempt_kicks,
            m.preempt_skipped,
            m.global_moves,
            m.nr_throttled,
            m.parked,
            m.bw_moves,
            m.cpuperf_sets,
            runtime,
            oncpu,
        );
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    if let Some(shell) = opts.completions {
        generate(
            shell,
            &mut Opts::command(),
            SCHEDULER_NAME,
            &mut std::io::stdout(),
        );
        return Ok(());
    }
    let only = opts.monitor.is_some();
    if opts.version {
        println!("{} {}", SCHEDULER_NAME, full_version());
        return Ok(());
    }
    if opts.help_stats {
        println!("stats: top");
        return Ok(());
    }
    if !only {
        simplelog::SimpleLogger::init(
            if opts.debug {
                simplelog::LevelFilter::Debug
            } else {
                simplelog::LevelFilter::Info
            },
            simplelog::Config::default(),
        )?;
        info!("{} {}", SCHEDULER_NAME, full_version());
        info!("Starting {} scheduler", SCHEDULER_NAME);
    }
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    ctrlc::set_handler(move || {
        sd.store(true, Ordering::Relaxed);
    })?;
    if let Some(intv) = opts.monitor.or(opts.stats) {
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = stats::monitor(Duration::from_secs_f64(intv), sd) {
                log::warn!("monitor failed: {e}");
            }
        });
        if only {
            let _ = jh.join();
            return Ok(());
        }
    }
    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    let mut sched = Scheduler::init(&opts, &mut open_object, shutdown.clone())?;
    sched.run(shutdown)?;
    info!("Scheduler exited");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_name_is_flow() {
        assert_eq!(SCHEDULER_NAME, "scx_flow");
    }

    #[test]
    fn max_cpus_matches_header() {
        assert_eq!(
            MAX_CPUS,
            crate::bpf_intf::flow_consts_FLOW_MAX_CPUS as usize
        );
    }

    #[test]
    fn batch_matches_header() {
        assert_eq!(
            crate::flow_edf::DISPATCH_BATCH,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_BATCH
        );
        assert_eq!(crate::flow_edf::DISPATCH_BATCH, 16);
        assert_eq!(
            crate::flow_tree::GLOBAL_SCAN,
            crate::bpf_intf::flow_consts_FLOW_GLOBAL_SCAN
        );
        assert_eq!(crate::flow_tree::GLOBAL_SCAN, 4);
    }

    #[test]
    fn vruntime_matches_header() {
        assert_eq!(crate::flow_vruntime::WEIGHT_BASE, 100);
        assert_eq!(crate::flow_vruntime::WEIGHT_MIN, 1);
        assert_eq!(crate::flow_vruntime::WEIGHT_MAX, 10_000);
        assert_eq!(
            crate::flow_tree::NODE_MAX,
            crate::bpf_intf::flow_consts_FLOW_NODE_MAX as u64
        );
        assert_eq!(
            crate::flow_tree::PARK_NR,
            crate::bpf_intf::flow_consts_FLOW_PARK_NR as u64
        );
        assert_eq!(
            crate::flow_tree::LLC_MAX,
            crate::bpf_intf::flow_consts_FLOW_LLC_MAX as u64
        );
        assert_eq!(
            crate::flow_tree::CPUFREQ_MIN_NS,
            crate::bpf_intf::flow_consts_FLOW_CPUFREQ_MIN_NS as u64
        );
    }

    #[test]
    fn starve_matches_header() {
        assert_eq!(
            crate::flow_edf::STARVE_NS,
            crate::bpf_intf::flow_consts_FLOW_STARVE_NS as u64
        );
        assert_eq!(crate::flow_edf::STARVE_NS, 2_000_000);
    }

    #[test]
    fn scan_matches_header() {
        assert_eq!(
            crate::flow_select::SCAN_BOUND as u64,
            crate::bpf_intf::flow_consts_FLOW_SCAN_BOUND as u64
        );
        assert_eq!(crate::flow_select::SCAN_BOUND, 8);
    }

    #[test]
    fn task_size_is_64() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>(), 64);
    }

    #[test]
    fn cpu_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_cpu_state>(), 8);
    }

    #[test]
    fn topo_size_is_8() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_topo>(), 8);
    }

    #[test]
    fn sched_stats_size_is_128() {
        assert_eq!(
            std::mem::size_of::<crate::bpf_intf::flow_sched_stats>(),
            128
        );
    }

    #[test]
    fn llc_size_is_24() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_llc_perf>(), 24);
    }

    #[test]
    fn cgrp_matches_header() {
        assert_eq!(
            crate::flow_cgrp::CGRP_MAX as u64,
            crate::bpf_intf::flow_consts_FLOW_CGRP_MAX as u64
        );
        assert_eq!(
            crate::flow_cgrp::CGRP_DEPTH_MAX as u64,
            crate::bpf_intf::flow_consts_FLOW_CGRP_DEPTH_MAX as u64
        );
        assert_eq!(
            crate::flow_cgrp::BW_PERIOD_MIN_US,
            crate::bpf_intf::flow_consts_FLOW_BW_PERIOD_MIN_US as u64
        );
        assert_eq!(crate::flow_cgrp::CGRP_MAX, 2048);
        assert_eq!(crate::flow_cgrp::CGRP_DEPTH_MAX, 8);
        assert_eq!(crate::flow_cgrp::BW_PERIOD_MIN_US, 1000);
    }

    #[test]
    fn cgrp_size_is_48() {
        assert_eq!(std::mem::size_of::<crate::bpf_intf::flow_cgrp_ctx>(), 48);
    }
}
