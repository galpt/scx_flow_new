// SPDX-License-Identifier: GPL-2.0
//! Scheduler run loop for the flow scheduler.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the skeleton, the link, and the stats server.

use std::mem::MaybeUninit;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::skel::Skel;
use log::info;
use log::warn;
use scx_arena::ArenaLib;
use scx_stats::prelude::*;
use scx_utils::NR_CPU_IDS;
use scx_utils::UserExitInfo;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::try_set_rlimit_infinity;
use scx_utils::uei_exited;
use scx_utils::uei_report;

use crate::BpfSkel;
use crate::BpfSkelBuilder;
use crate::cli::Opts;
use crate::cli::SCHEDULER_NAME;
use crate::stats::Metrics;

/// Arena node size lock. The BPF queue node holds one hundred thirty six
/// bytes beside the two hundred sixteen byte task state, so per task memory
/// stays within five hundred twelve bytes. A drift fails the build here.
const _: () = assert!(std::mem::size_of::<crate::bpf_intf::flow_arena_task>() == 136);

/// Task state size lock. The state holds two hundred sixteen bytes with the
/// run ring plus range plus flag plus sum, so state plus node stay within
/// five hundred twelve bytes per task. A drift fails the build here.
const _: () = assert!(std::mem::size_of::<crate::bpf_intf::flow_task_ctx>() == 216);

/// CPU seed size lock. The seed holds the CPU id plus the cluster hint
/// plus three size buckets plus one reserved byte beside the pad, so the
/// row stays sixteen bytes with no growth. A drift fails the build here.
const _: () = assert!(std::mem::size_of::<crate::bpf_intf::flow_cpu_ctx>() == 16);

/*
 * Scheduler holds the skeleton, the link, and the stats server.
 * It drives the run loop until shutdown or exit. The arena library
 * stays alive for the whole run so queue and topology memory stays
 * valid while the scheduler is attached. Placement plus drain read the
 * seed plus the tree in BPF, so the run loop adds no per task cache state.
 */
pub(crate) struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<(), Metrics>,
    _arenalib: ArenaLib,
}

/// One list tool run with no flags. Standard output caps at one
/// megabyte plus sixty four thousand lines max. Timeout is ten
/// seconds which is ten thousand milliseconds. PATH lookup matches
/// the absolute path byte for byte per the gate manifest. Sudo keeps
/// root env clean with no user env pass. No retry follows on failure.
fn run_lstopo_once(prog: &str) -> Result<String> {
    use std::process::Command;
    // Blocking run with no flags. The timeout wrapper bounds the
    // wait at ten seconds with no retry on any failure.
    let out = Command::new("timeout")
        .arg("10s")
        .arg(prog)
        .output()
        .context("list tool spawn failed")?;
    if !out.status.success() {
        anyhow::bail!("list tool exit failed");
    }
    // Standard output caps at one megabyte.
    let mut bytes: Vec<u8> = out.stdout;
    bytes.truncate(1_048_576);
    // Empty standard error is expected. Content is ignored here.
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    // Line cap keeps sixty four thousand lines max.
    let mut capped = String::new();
    let mut count: usize = 0;
    for line in text.lines() {
        if count >= 64_000 {
            break;
        }
        capped.push_str(line);
        capped.push('\n');
        count = count.wrapping_add(1);
    }
    if capped.is_empty() {
        anyhow::bail!("list tool empty output");
    }
    Ok(capped)
}

/// Fetch the true size view before topology discovery. Single attempt
/// with no retry. Any failure returns none so the seed keeps the
/// aggregated fallback with BPF defaults. Never panics.
fn fetch_lstopo_view() -> Option<crate::lstopo::LstopoView> {
    // PATH lookup first. The absolute path reads
    // /usr/bin/lstopo-no-graphics and matches PATH byte for byte.
    let text: String = match run_lstopo_once("lstopo-no-graphics") {
        Ok(v) => v,
        Err(_) => return None,
    };
    match crate::lstopo::parse_lstopo_text(&text) {
        Ok(v) => Some(v),
        Err(_) => None,
    }
}

impl<'a> Scheduler<'a> {
    pub fn init(
        opts: &'a Opts,
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();
        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(skel_builder, open_object, flow_ops, open_opts)
            .context("failed to open BPF object (check dmesg)")?;
        skel.struct_ops.flow_ops_mut().exit_dump_len = opts.exit_dump_len;
        // Blocking list fetch sits before topology discovery.
        // After arena setup the seed consumes the view.
        let lstopo_view: Option<crate::lstopo::LstopoView> = fetch_lstopo_view();
        let topo = match scx_utils::Topology::new().context("topology discovery") {
            Ok(t) => Some(t),
            Err(e) => {
                warn!("topology discovery failed, using defaults: {e:#}");
                None
            }
        };
        {
            // Thread shape defaults on in BPF so a missed seed stays conservative.
            let smt_flag = topo.as_ref().map(crate::topology::smt_on).unwrap_or(true);
            match skel.maps.data_data.as_mut() {
                Some(data) => data.flow_smt_enabled = if smt_flag { 1 } else { 0 },
                None => warn!("smt seed missed, using kernel default"),
            }
            // Arena sizing needs the host CPU count before load so the bitmap
            // init sees a valid value and the topology tree can build.
            match skel.maps.rodata_data.as_mut() {
                Some(rodata) => rodata.nr_cpu_ids = *NR_CPU_IDS as u32,
                None => warn!("nr_cpu_ids seed missed, arena init will fail"),
            }
        }
        let mut skel = scx_ops_load!(skel, flow_ops, uei)?;
        // Build the arena and the topology tree before any queue exists.
        // The BPF init fails closed when the tree is missing, so a setup
        // failure here never reaches attach.
        let task_size = std::mem::size_of::<crate::bpf_intf::flow_arena_task>();
        let arenalib = ArenaLib::setup(skel.object_mut(), task_size, 0, *NR_CPU_IDS)
            .context("arena setup failed")?;
        if let Some(t) = topo.as_ref() {
            // Summary plus brief at info.
            let seed_text: Result<String> = match lstopo_view.as_ref() {
                Some(v) => crate::topology::seed_topology_lstopo(&mut skel, t, v),
                None => crate::topology::seed_topology(&mut skel, t),
            };
            match seed_text {
                Ok(text) => info!("Topology: {text}"),
                Err(e) => warn!("topology seed failed, using BPF defaults: {e:#}"),
            }
            info!("Topology: {}", crate::topology::describe_topo_summary(t));
            info!("{}", crate::topology::describe_sched_use(t));
            // Per core true sizes at info with a sixty four line cap.
            // The tree stays at debug.
            let core_lines = crate::topology::render_per_core_lines(t, lstopo_view.as_ref());
            let total_cores = core_lines.len();
            if total_cores > 64 {
                for line in core_lines.into_iter().take(64) {
                    info!("Topology: {line}");
                }
                info!("Topology: ...+{} more", total_cores - 64);
            } else {
                for line in core_lines {
                    info!("Topology: {line}");
                }
            }
            // Tree at debug.
            if log::log_enabled!(log::Level::Debug) {
                let topo_lines = crate::topology::render_topo_lines(t);
                // Cap keeps debug bounded.
                let total = topo_lines.len();
                if total > 64 {
                    for line in topo_lines.into_iter().take(64) {
                        log::debug!("Topology: {line}");
                    }
                    log::debug!("Topology: ...+{} more", total - 64);
                } else {
                    for line in topo_lines {
                        log::debug!("Topology: {line}");
                    }
                }
            }
        }
        let struct_ops = scx_ops_attach!(skel, flow_ops)?;
        let stats_server = StatsServer::new(crate::stats::server_data()).launch()?;
        Ok(Self {
            skel,
            struct_ops: Some(struct_ops),
            stats_server,
            _arenalib: arenalib,
        })
    }

    fn exited(&mut self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    /// Sum per LLC counters into one view.
    /// A failed map read warns and keeps zeros for that entry.
    fn get_metrics(&self) -> Metrics {
        crate::metrics::collect(&self.skel)
    }

    /// One row per LLC for debug logs. Reuses the same fold guards.
    fn log_per_llc(&self) {
        if !log::log_enabled!(log::Level::Debug) {
            return;
        }
        for (llc, row) in crate::metrics::collect_per_llc(&self.skel) {
            let mut buf: Vec<u8> = Vec::new();
            if row.format_llc(&mut buf, llc).is_ok() {
                log::debug!("{}", String::from_utf8_lossy(&buf).trim_end());
            }
        }
    }

    pub fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (res_ch, req_ch) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match req_ch.recv_timeout(Duration::from_secs(1)) {
                Ok(()) => {
                    res_ch.send(self.get_metrics())?;
                    self.log_per_llc();
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(e) => Err(e)?,
            }
        }
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_> {
    fn drop(&mut self) {
        info!("Unregister {SCHEDULER_NAME} scheduler");
    }
}

/// Drive the restart loop until shutdown or a non-restart exit.
/// Holds shutdown, the monitor thread, and the open object.
/// Restart follows the exit info. A restart starts a new instance.
pub fn drive(opts: &Opts) -> Result<()> {
    use anyhow::Context as _;
    let shutdown = Arc::new(AtomicBool::new(false));
    let sd = shutdown.clone();
    ctrlc::set_handler(move || sd.store(true, Ordering::Relaxed))
        .context("Error setting Ctrl-C handler")?;
    if let Some(intv) = opts.monitor.or(opts.stats) {
        let dur = crate::cli::poll_interval_secs(intv)?;
        let sd = shutdown.clone();
        let jh = std::thread::spawn(move || {
            if let Err(e) = crate::stats::monitor(dur, sd) {
                warn!("monitor failed: {e:#}");
            }
        });
        if opts.monitor.is_some() {
            let _ = jh.join();
            return Ok(());
        }
    }
    let mut open_object = MaybeUninit::<libbpf_rs::OpenObject>::uninit();
    loop {
        let mut sched = Scheduler::init(opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }
    info!("Scheduler exited");
    Ok(())
}
