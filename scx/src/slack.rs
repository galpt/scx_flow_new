// SPDX-License-Identifier: GPL-2.0
//! Timer slack of the latency critical tasks of --lowlatency.
//!
//! The kernel may fire the timer of a fair class task anywhere in a window
//! after the time the task asked for, 50 us long by default, so that one
//! interrupt can serve several timers. A task that sleeps on timers waits
//! out that window on every wakeup, however fast the scheduler then puts
//! it on a CPU. With --lowlatency, the BPF side reports each task that
//! becomes latency critical, see flow_lowlat_report(), and its slack is set
//! to one nanosecond. Zero would not do, as the kernel reads it as a
//! request for the default.
//!
//! The old slack of each task is written back when the scheduler stops or
//! restarts, but only to a task that still has the slack written here, so
//! a task that chose its own in the meantime keeps it. A thread id may
//! belong to another task by then, so the start time of the task is kept
//! with it and checked first. The old values are also saved in a file
//! under /run, so that the next start writes them back when the scheduler
//! was killed before it could.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use log::info;
use log::warn;

/// The tasks whose slack TimerSlack lowered, one "tid start old" line each.
/// /run is emptied at boot, when those tasks are gone as well.
const SAVED_SLACK: &str = "/run/scx_flow/timerslack";

/// Where SAVED_SLACK is written before it replaces the old one.
const SAVED_SLACK_NEW: &str = "/run/scx_flow/timerslack.new";

/// The slack of a latency critical task, in nanoseconds.
const CRITICAL_SLACK: u64 = 1;

/// The most tasks followed at once, which bounds the memory and the size of
/// SAVED_SLACK.
const MAX_TASKS: usize = 1024;

/// The policy of the tasks whose slack is lowered. Realtime and deadline
/// tasks have no slack, and batch and idle tasks are in no hurry.
const SCHED_NORMAL: u64 = 0;

fn slack_path(tid: i32) -> String {
    format!("/proc/{tid}/timerslack_ns")
}

/// The start time and the scheduling policy in the contents of
/// /proc/<tid>/stat, which are fields 22 and 41.
fn parse_stat(stat: &str) -> Option<(u64, u64)> {
    // The name in field 2 may hold spaces and parentheses of its own, so
    // the fields are counted from the last closing one, with field 3 next.
    let fields: Vec<&str> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
    let start = fields.get(22 - 3)?.parse().ok()?;
    let policy = fields.get(41 - 3)?.parse().ok()?;
    Some((start, policy))
}

fn task_stat(tid: i32) -> Option<(u64, u64)> {
    parse_stat(&fs::read_to_string(format!("/proc/{tid}/stat")).ok()?)
}

fn read_slack(tid: i32) -> Option<u64> {
    fs::read_to_string(slack_path(tid))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// What a task looked like before its slack was lowered.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Saved {
    /// Start time of the task, field 22 of its stat.
    start: u64,
    /// Its slack before.
    old: u64,
}

/// Parse the contents of SAVED_SLACK, skipping lines that do not parse.
fn parse_saved(saved: &str) -> Vec<(i32, Saved)> {
    saved
        .lines()
        .filter_map(|line| {
            let mut words = line.split(' ');
            let tid = words.next()?.parse().ok()?;
            let start = words.next()?.parse().ok()?;
            let old = words.next()?.parse().ok()?;
            words
                .next()
                .is_none()
                .then_some((tid, Saved { start, old }))
        })
        .collect()
}

/// Replace SAVED_SLACK with @tasks, all at once, so that a crash in the
/// middle leaves either the old list or the new one.
fn save(tasks: &BTreeMap<i32, Saved>) -> io::Result<()> {
    let lines: String = tasks
        .iter()
        .map(|(tid, s)| format!("{tid} {} {}\n", s.start, s.old))
        .collect();
    if let Some(dir) = Path::new(SAVED_SLACK).parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(SAVED_SLACK_NEW, lines)?;
    fs::rename(SAVED_SLACK_NEW, SAVED_SLACK)
}

/// Remove SAVED_SLACK, and its directory once nothing else is in it.
fn forget_saved() {
    let _ = fs::remove_file(SAVED_SLACK_NEW);
    if let Err(e) = fs::remove_file(SAVED_SLACK)
        && e.kind() != io::ErrorKind::NotFound
    {
        warn!("failed to remove {SAVED_SLACK}: {e}");
    }
    if let Some(dir) = Path::new(SAVED_SLACK).parent() {
        let _ = fs::remove_dir(dir);
    }
}

/// Write the old slack back to @tid if it is still the task of @saved and
/// still has the slack written here. Returns whether it was written.
fn restore(tid: i32, saved: &Saved) -> bool {
    task_stat(tid).is_some_and(|(start, _)| start == saved.start)
        && read_slack(tid) == Some(CRITICAL_SLACK)
        && fs::write(slack_path(tid), saved.old.to_string()).is_ok()
}

/// Write back the slack that a scheduler which was killed left behind. A
/// task that is gone, or that is not the one the line was written for, is
/// skipped, so the file is always removed after.
pub fn restore_saved_slack() {
    let Ok(saved) = fs::read_to_string(SAVED_SLACK) else {
        return;
    };
    let restored = parse_saved(&saved)
        .iter()
        .filter(|(tid, s)| restore(*tid, s))
        .count();
    if restored > 0 {
        info!("restored the timer slack of {restored} tasks left behind by an earlier run");
    }
    forget_saved();
}

/// The latency critical tasks of --lowlatency get the smallest timer slack,
/// see the module comment. The old slack is written back when dropped.
pub struct TimerSlack {
    tasks: BTreeMap<i32, Saved>,
    /// SAVED_SLACK was left by an earlier run, so nothing is touched.
    disabled: bool,
}

/// Nothing is followed yet. Nothing is touched either if an earlier run
/// left SAVED_SLACK behind that could not be removed, as the slack of the
/// tasks is not the old one then.
impl Default for TimerSlack {
    fn default() -> Self {
        let disabled = Path::new(SAVED_SLACK).exists();
        if disabled {
            warn!("{SAVED_SLACK} is left from an earlier run, leaving the timer slack alone");
        }
        Self {
            tasks: BTreeMap::new(),
            disabled,
        }
    }
}

impl TimerSlack {
    /// Drop the tasks that exited, whose thread ids may be in use again.
    fn prune(&mut self) {
        self.tasks
            .retain(|tid, s| task_stat(*tid).is_some_and(|(start, _)| start == s.start));
    }

    /// Lower the slack of the SCHED_NORMAL tasks of @tids. Tasks that cannot
    /// be read or written, as when they exited, are skipped. The old values
    /// are saved before anything is written.
    pub fn lower(&mut self, tids: impl IntoIterator<Item = i32>) {
        if self.disabled {
            return;
        }
        let mut fresh = Vec::new();
        for tid in tids {
            let Some((start, policy)) = task_stat(tid) else {
                continue;
            };
            if policy != SCHED_NORMAL || self.tasks.get(&tid).is_some_and(|s| s.start == start) {
                continue;
            }
            let Some(old) = read_slack(tid) else {
                continue;
            };
            if old == CRITICAL_SLACK {
                continue;
            }
            if self.tasks.len() >= MAX_TASKS && !self.tasks.contains_key(&tid) {
                self.prune();
                if self.tasks.len() >= MAX_TASKS {
                    continue;
                }
            }
            self.tasks.insert(tid, Saved { start, old });
            fresh.push(tid);
        }
        if fresh.is_empty() {
            return;
        }
        if let Err(e) = save(&self.tasks) {
            warn!("failed to save the timer slack to {SAVED_SLACK}, leaving it alone: {e}");
            for tid in fresh {
                self.tasks.remove(&tid);
            }
            return;
        }
        for tid in fresh {
            if fs::write(slack_path(tid), CRITICAL_SLACK.to_string()).is_err() {
                self.tasks.remove(&tid);
            }
        }
    }
}

impl Drop for TimerSlack {
    fn drop(&mut self) {
        if self.disabled {
            return;
        }
        for (tid, saved) in &self.tasks {
            restore(*tid, saved);
        }
        forget_saved();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields() {
        let mut stat = String::from("4242 (a) b (c)) S");
        for field in 4..=52 {
            stat.push_str(&format!(" {field}"));
        }
        assert_eq!(parse_stat(&stat), Some((22, 41)));
        assert_eq!(parse_stat("4242 (short) S 1 2"), None);
        assert_eq!(parse_stat("no name here"), None);
    }

    #[test]
    fn saved_lines() {
        let saved = "12 345 50000\n13 346 1000 7\nx 1 2\n14 347\n15 348 200\n";
        assert_eq!(
            parse_saved(saved),
            [
                (
                    12,
                    Saved {
                        start: 345,
                        old: 50000
                    }
                ),
                (
                    15,
                    Saved {
                        start: 348,
                        old: 200
                    }
                ),
            ]
        );
    }
}
