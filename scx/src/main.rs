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
/* Flow helpers are unit tested. */
#[allow(dead_code)]
mod flow;
mod stats;
mod topology;
mod webui;

use std::mem::size_of;
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
/* Cpu bound shared with the BPF header. */
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
    /* Static per cpu cards seeded at attach. */
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
        /* Honor exiting tasks and queued wakeups. */
        let flags = *compat::SCX_OPS_ENQ_EXITING
            | *compat::SCX_OPS_ENQ_LAST
            | *compat::SCX_OPS_ENQ_MIGRATION_DISABLED
            | *compat::SCX_OPS_ALLOW_QUEUED_WAKEUP;
        skel.struct_ops.flow_ops_mut().flags = flags;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
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
        let cpu_static = if opts.no_webui {
            Vec::new()
        } else {
            topology::web_cpu_static()
        };
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
            l0_placements: s.l0_placements,
            l1_placements: s.l1_placements,
            l2_placements: s.l2_placements,
            demotions: s.demotions,
            steals: s.steals,
            dispatches: s.dispatches,
            enq_no_tctx: s.enq_no_tctx,
        }
    }

    /*
     * Read one cpu state without heap use. Failed
     * lookups yield an idle view.
     */
    fn read_cpu(&self, cpu: usize) -> flow_cpu_state {
        let idle = flow_cpu_state {
            running_level: -1,
            running_pid: 0,
            scan_off: 0,
            pad: 0,
        };
        if cpu >= MAX_CPUS {
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

    /* Read the live per level means from BPF memory. */
    fn read_means(&self) -> Vec<u64> {
        let bss = self.skel.maps.bss_data.as_ref().expect("bss missing");
        bss.flow_mean_ns.to_vec()
    }

    /*
     * Dashboard snapshot. Merges the static cards with
     * live state and live means. Gauges only, no deltas.
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
            e.running_level = st.running_level;
            e.running_pid = st.running_pid;
            per_cpu.push(e);
        }
        let stats = self.get_metrics();
        let mean_ns = self.read_means();
        stats::WebMetrics {
            stats,
            per_cpu,
            mean_ns,
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
        info!(
            "exit l0={} l1={} l2={} demote={} steal={} \
            disp={} runtime={} oncpu={}",
            m.l0_placements,
            m.l1_placements,
            m.l2_placements,
            m.demotions,
            m.steals,
            m.dispatches,
            m.total_runtime,
            m.on_cpu,
        );
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

/* Read one u64 map value for tests. Unused in run. */
#[allow(dead_code)]
fn map_u64_size() -> usize {
    size_of::<u64>()
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
    fn batch_and_scan_match_header() {
        assert_eq!(
            crate::flow::DISPATCH_BATCH,
            crate::bpf_intf::flow_consts_FLOW_DISPATCH_MAX_BATCH
        );
        assert_eq!(
            crate::flow::STEAL_SCAN_MAX,
            crate::bpf_intf::flow_consts_FLOW_STEAL_SCAN_MAX
        );
        assert_eq!(
            crate::flow::STEAL_L0,
            crate::bpf_intf::flow_consts_FLOW_STEAL_L0
        );
        assert_eq!(
            crate::flow::STEAL_L1,
            crate::bpf_intf::flow_consts_FLOW_STEAL_L1
        );
        assert_eq!(
            crate::flow::STEAL_L2,
            crate::bpf_intf::flow_consts_FLOW_STEAL_L2
        );
    }
}
