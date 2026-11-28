// SPDX-License-Identifier: GPL-2.0
//! Command line options of scx_flow.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::time::Duration;

use anyhow::Result;
use clap::Parser;
use clap_complete::Shell;
use scx_utils::libbpf_clap_opts::LibbpfOpts;

use crate::bpf_intf;

pub const SCHEDULER_NAME: &str = "scx_flow";

pub fn full_version() -> String {
    scx_utils::build_id::full_version(env!("CARGO_PKG_VERSION"))
}

/// Log to stderr with local timestamps, at debug level when @verbose.
pub fn init_logging(verbose: bool) -> Result<()> {
    let loglevel = if verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_offset_to_local()
        .expect("Failed to set local time offset")
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        loglevel,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    Ok(())
}

/// Statistics interval in seconds, which must be above zero and at most
/// one hour.
pub fn poll_interval_secs(v: f64) -> Result<Duration> {
    if !v.is_finite() || v <= 0.0 || v > 3600.0 {
        anyhow::bail!("invalid statistics interval {v}");
    }
    Ok(Duration::from_secs_f64(v))
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version, disable_version_flag = true)]
pub struct Opts {
    /// Print statistics every this many seconds while scheduling.
    #[clap(long)]
    pub stats: Option<f64>,

    /// Print statistics of an already running instance every this many
    /// seconds, without starting the scheduler.
    #[clap(long)]
    pub monitor: Option<f64>,

    /// Tune scheduling for the wakeup latencies that helicoprion measures.
    /// Without it, tasks are scheduled as in 5.2.28.
    #[clap(long)]
    pub helicoprion: bool,

    /// Schedule for the highest frame rates and the lowest input latency,
    /// at the cost of higher power use.
    #[clap(long, conflicts_with = "helicoprion")]
    pub performance: bool,

    /// Do what --performance does, and let latency critical wakeups take
    /// a CPU at once, preempting a task that computes if no CPU is idle.
    /// Latency critical tasks get the smallest timer slack until the
    /// scheduler stops, and every CPU only polls while idle.
    #[clap(long, conflicts_with_all = ["helicoprion", "performance"])]
    pub lowlatency: bool,

    /// Enable debug output, including libbpf messages.
    #[clap(short = 'v', long, action = clap::ArgAction::SetTrue)]
    pub verbose: bool,

    /// Size of the debug dump buffer printed on exit, in bytes. Zero keeps
    /// the kernel default.
    #[clap(long, default_value = "0")]
    pub exit_dump_len: u32,

    /// Print the version and exit.
    #[clap(short = 'V', long, action = clap::ArgAction::SetTrue)]
    pub version: bool,

    /// Describe the statistics and exit.
    #[clap(long)]
    pub help_stats: bool,

    /// Generate shell completions and exit.
    #[clap(long, value_name = "SHELL", hide = true)]
    pub completions: Option<Shell>,

    #[clap(flatten, next_help_heading = "Libbpf Options")]
    pub libbpf: LibbpfOpts,
}

/// The mode the scheduler runs in, from the mode flags, which exclude each
/// other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Default,
    Helicoprion,
    Performance,
    LowLatency,
}

impl Mode {
    /// The `enum flow_mode` value of the BPF program.
    pub fn bpf(self) -> u32 {
        match self {
            Mode::Default => bpf_intf::flow_mode_FLOW_MODE_DEFAULT,
            Mode::Helicoprion => bpf_intf::flow_mode_FLOW_MODE_HELICOPRION,
            Mode::Performance => bpf_intf::flow_mode_FLOW_MODE_PERFORMANCE,
            Mode::LowLatency => bpf_intf::flow_mode_FLOW_MODE_LOWLATENCY,
        }
    }

    /// --performance, or --lowlatency, which does everything it does.
    pub fn performance(self) -> bool {
        matches!(self, Mode::Performance | Mode::LowLatency)
    }

    /// How the startup log names the mode, if it has extras to report.
    pub fn label(self) -> Option<&'static str> {
        match self {
            Mode::Performance => Some("Performance mode"),
            Mode::LowLatency => Some("Low latency mode"),
            Mode::Default | Mode::Helicoprion => None,
        }
    }
}

impl Opts {
    pub fn mode(&self) -> Mode {
        if self.lowlatency {
            Mode::LowLatency
        } else if self.performance {
            Mode::Performance
        } else if self.helicoprion {
            Mode::Helicoprion
        } else {
            Mode::Default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(args: &[&str]) -> Option<Mode> {
        let argv = std::iter::once("scx_flow").chain(args.iter().copied());
        Opts::try_parse_from(argv).ok().map(|o| o.mode())
    }

    #[test]
    fn modes_exclude_each_other() {
        assert_eq!(mode_of(&[]), Some(Mode::Default));
        assert_eq!(mode_of(&["--helicoprion"]), Some(Mode::Helicoprion));
        assert_eq!(mode_of(&["--performance"]), Some(Mode::Performance));
        assert_eq!(mode_of(&["--lowlatency"]), Some(Mode::LowLatency));
        for pair in [
            ["--performance", "--helicoprion"],
            ["--lowlatency", "--helicoprion"],
            ["--lowlatency", "--performance"],
        ] {
            assert_eq!(mode_of(&pair), None);
        }
    }

    #[test]
    fn lowlatency_builds_on_performance() {
        assert!(Mode::LowLatency.performance());
        assert!(Mode::Performance.performance());
        assert!(!Mode::Helicoprion.performance());
        assert!(!Mode::Default.performance());
        assert_ne!(Mode::LowLatency.bpf(), Mode::Performance.bpf());
    }

    #[test]
    fn interval_bounds() {
        assert!(poll_interval_secs(0.5).is_ok());
        assert!(poll_interval_secs(3600.0).is_ok());
        for bad in [0.0, -1.0, 3600.5, f64::NAN, f64::INFINITY] {
            assert!(poll_interval_secs(bad).is_err());
        }
    }
}
