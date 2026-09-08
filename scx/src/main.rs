/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Flow scheduler front end. Loads the BPF object, serves
 * stats and the dashboard, and drives the run loop until
 * shutdown or exit.
 */
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;
pub use bpf_intf::*;
mod config;
mod flow;
mod stats;
mod topology;
mod webui;

use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::CommandFactory;
use clap::Parser;
use clap_complete::generate;
use clap_complete::Shell;
use crossbeam::channel::RecvTimeoutError;
use log::info;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::compat;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::UserExitInfo;

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
struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    /* Dashboard sender. None when disabled. */
    webui_tx: Option<crossbeam::channel::Sender<stats::WebMetrics>>,
    /* Static per-CPU cards seeded at attach. */
    cpu_static: Vec<stats::PerCpuMetrics>,
    /* Live frequency cache for the cards. */
    cur_freq_khz: Vec<u64>,
    freq_read_at: Option<std::time::Instant>,
    started_at: std::time::Instant,
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
        /* Honor exiting tasks and waiting wakeups. */
        let flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        skel.struct_ops.flow_ops_mut().flags = flags;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        /* Seed the LLC table before load. Fail open. */
        let cards = topology::web_cpu_static();
        if let Some(bss) = skel.maps.bss_data.as_mut() {
            let (table, nr) = topology::llc_seed(&cards);
            bss.flow_cpu_llc = table;
            bss.flow_llc_nr = nr;
        }
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        let _ = &mut skel;
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
        let cpu_static = if opts.no_webui { Vec::new() } else { cards };
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            webui_tx,
            cpu_static,
            cur_freq_khz: Vec::with_capacity(MAX_CPUS),
            freq_read_at: None,
            started_at: std::time::Instant::now(),
        })
    }

    fn get_metrics(&self) -> Metrics {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        let s = &bss.flow_stats;
        Metrics {
            on_cpu: s.on_cpu,
            total_runtime: s.total_runtime,
            uptime_ns: self.started_at.elapsed().as_nanos() as u64,
            enq_tier0: s.enq_tier0,
            enq_tier1: s.enq_tier1,
            demotions: s.demotions,
            promotions: s.promotions,
            serves_tier0: s.serves_tier0,
            serves_tier1: s.serves_tier1,
            deficit_serves: s.deficit_serves,
            kicks: s.kicks,
            preempts: s.preempts,
            enq_no_tctx: s.enq_no_tctx,
        }
    }

    /*
     * Read one CPU state without heap use. Failed
     * lookups yield an idle view.
     */
    fn read_cpu(&self, cpu: usize) -> flow_cpu_state {
        let idle = flow_cpu_state {
            running_est: 0,
            running_pid: 0,
            running_tier: 0,
            served0: 0,
            last_preempt_at: 0,
        };
        if cpu >= MAX_CPUS {
            return idle;
        }
        if !crate::flow::tier_ok(0) {
            return idle;
        }
        let fd = self.skel.maps.cpu_state_stor.as_fd().as_raw_fd();
        let key = cpu as u32;
        let mut out = MaybeUninit::<flow_cpu_state>::uninit();
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
     * Fixed slices per tier. Each entry holds the slice
     * of one tier in nanos.
     */
    fn read_quanta(&self) -> [u64; 2] {
        [crate::flow::quantum_tier(0), crate::flow::quantum_tier(1)]
    }

    /* Read the joined task count per tier. */
    fn read_waiting(&self) -> [u64; 2] {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        bss.flow_tier_nr
    }

    /*
     * Dashboard snapshot. Merges the static cards with
     * live state and per tier slices. Gauges only, no
     * deltas. Frequency stays display only and never
     * feeds placement or division.
     */
    fn get_web_metrics(&mut self) -> stats::WebMetrics {
        let nr = self
            .skel
            .maps
            .bss_data
            .as_ref()
            .expect("bss missing")
            .nr_cpu_ids as usize;
        let nr = nr.min(MAX_CPUS);
        let now = std::time::Instant::now();
        let old = self
            .freq_read_at
            .is_none_or(|t| now.duration_since(t).as_secs() >= 1);
        if old {
            self.cur_freq_khz.clear();
            for cpu in 0..nr {
                self.cur_freq_khz
                    .push(topology::current_freq_khz(cpu as u32));
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
            e.running_tier = st.running_tier;
            per_cpu.push(e);
        }
        let stats = self.get_metrics();
        let quanta_per_tier = self.read_quanta();
        let waiting_per_tier = self.read_waiting();
        stats::WebMetrics {
            stats,
            per_cpu,
            quanta_per_tier,
            waiting_per_tier,
        }
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
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
        let enq = m.enq_tier0 + m.enq_tier1;
        let (run0, run1) = (m.serves_tier0, m.serves_tier1);
        let deficit = m.deficit_serves;
        let (runtime, oncpu) = (m.total_runtime, m.on_cpu);
        info!(
            "exit enq={} run={}/{} deficit={} runtime={} oncpu={}",
            enq, run0, run1, deficit, runtime, oncpu,
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
            crate::flow::DISPATCH_BATCH as u64,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH as u64
        );
    }

    #[test]
    fn tiers_match_header() {
        assert_eq!(
            crate::flow::NTIERS as u64,
            crate::bpf_intf::flow_consts_FLOW_NTIERS as u64
        );
        assert_eq!(
            crate::flow::QUANTUM_TIER0_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_TIER0_NS as u64
        );
        assert_eq!(
            crate::flow::QUANTUM_TIER1_NS,
            crate::bpf_intf::flow_consts_FLOW_QUANTUM_TIER1_NS as u64
        );
        assert_eq!(
            crate::flow::SHORT_BOUND_NS,
            crate::bpf_intf::flow_consts_FLOW_SHORT_BOUND_NS as u64
        );
        assert_eq!(
            crate::flow::PROMOTE_STREAK as u64,
            crate::bpf_intf::flow_consts_FLOW_PROMOTE_STREAK as u64
        );
        assert_eq!(
            crate::flow::STREAK_CAP as u64,
            crate::bpf_intf::flow_consts_FLOW_STREAK_CAP as u64
        );
        assert_eq!(
            crate::flow::DEFICIT_SERVES,
            crate::bpf_intf::flow_consts_FLOW_DEFICIT_SERVES as u64
        );
    }

    #[test]
    fn dsq_and_gap_match_header() {
        assert_eq!(
            crate::flow::DSQ_BATCH,
            crate::bpf_intf::flow_consts_FLOW_DSQ_BATCH as u64
        );
        assert_eq!(
            crate::flow::DSQ_PARK,
            crate::bpf_intf::flow_consts_FLOW_DSQ_PARK as u64
        );
        assert_eq!(
            crate::flow::PREEMPT_GAP_NS,
            crate::bpf_intf::flow_consts_FLOW_PREEMPT_GAP_NS as u64
        );
        assert_eq!(
            crate::flow::EST_MIN_NS,
            crate::bpf_intf::flow_consts_FLOW_EST_MIN_NS as u64
        );
        assert_eq!(
            crate::flow::EST_MAX_NS,
            crate::bpf_intf::flow_consts_FLOW_EST_MAX_NS as u64
        );
        assert_eq!(
            crate::flow::LLC_UNKNOWN,
            crate::bpf_intf::flow_consts_FLOW_LLC_UNKNOWN as u32
        );
    }

    #[test]
    fn quanta_match_tier_helpers() {
        assert_eq!(crate::flow::quantum_tier(0), 500_000);
        assert_eq!(crate::flow::quantum_tier(1), 8_000_000);
        assert!(crate::flow::tier_ok(0));
        assert!(crate::flow::tier_ok(1));
        assert!(!crate::flow::tier_ok(2));
    }
}
