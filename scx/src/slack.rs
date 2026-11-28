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
//! The kernel copies the slack of a task into every thread and process it
//! creates, so those start with one nanosecond too and nobody reports them.
//! The file therefore also holds the time the first slack was lowered. When
//! the old slack is written back, the threads in /proc that started after
//! that time, run under SCHED_NORMAL and have exactly one nanosecond get the
//! old slack of the task they most likely came from: a task of the same
//! process, else of the nearest ancestor process that has one, else 50 us,
//! the default of init. A thread that chose one nanosecond for itself in
//! that time is reset too, which is not worth telling apart. The scan only
//! runs when the slack is written back. The kernel copies the default slack
//! of a task as well, which userspace cannot change, so such a thread that
//! resets its slack with prctl(PR_SET_TIMERSLACK, 0) can still end up with
//! one nanosecond.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use log::info;
use log::warn;

/// The tasks whose slack TimerSlack lowered, one "tid start old" line each,
/// after a "since <ticks>" line with the time the first of them was lowered.
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

/// The slack that init and kthreadd start with, and so most tasks inherit.
const DEFAULT_SLACK: u64 = 50000;

/// The most threads looked at when the slack of inherited threads is
/// written back, which bounds the time spent while the scheduler stops.
const MAX_SCAN: usize = 1 << 18;

/// The most parent processes followed to find the slack a thread inherited.
const MAX_ANCESTORS: usize = 64;

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

/// The thread group and the parent process in the contents of
/// /proc/<tid>/status.
fn parse_status(status: &str) -> Option<(i32, i32)> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse().ok())
    };
    Some((field("Tgid:")?, field("PPid:")?))
}

fn task_status(tid: i32) -> Option<(i32, i32)> {
    parse_status(&fs::read_to_string(format!("/proc/{tid}/status")).ok()?)
}

/// The time since boot in clock ticks, the unit of field 22 of the stat of a
/// task, from the contents of /proc/uptime. Both count the time the system
/// was suspended, and both are hundredths of a second.
fn parse_uptime(uptime: &str) -> Option<u64> {
    let (secs, frac) = uptime.split_whitespace().next()?.split_once('.')?;
    let hundredths = frac.get(..2).unwrap_or(frac);
    let hundredths = if hundredths.len() == 1 {
        hundredths.parse::<u64>().ok()? * 10
    } else {
        hundredths.parse().ok()?
    };
    Some(secs.parse::<u64>().ok()?.checked_mul(100)? + hundredths)
}

fn boot_ticks() -> Option<u64> {
    parse_uptime(&fs::read_to_string("/proc/uptime").ok()?)
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

/// The contents of SAVED_SLACK.
#[derive(Debug, Default, PartialEq)]
struct SavedState {
    /// When the first slack was lowered, as boot_ticks(). A file from before
    /// this was written has none.
    since: Option<u64>,
    tasks: Vec<(i32, Saved)>,
}

/// Parse the contents of SAVED_SLACK, skipping lines that do not parse.
fn parse_saved(saved: &str) -> SavedState {
    let mut state = SavedState::default();
    for line in saved.lines() {
        if let Some(ticks) = line.strip_prefix("since ") {
            if state.since.is_none() {
                state.since = ticks.parse().ok();
            }
            continue;
        }
        let mut words = line.split(' ');
        let task = (|| {
            let tid = words.next()?.parse().ok()?;
            let start = words.next()?.parse().ok()?;
            let old = words.next()?.parse().ok()?;
            words
                .next()
                .is_none()
                .then_some((tid, Saved { start, old }))
        })();
        state.tasks.extend(task);
    }
    state
}

/// Replace SAVED_SLACK with @tasks, all at once, so that a crash in the
/// middle leaves either the old list or the new one.
fn save(since: Option<u64>, tasks: &BTreeMap<i32, Saved>) -> io::Result<()> {
    let header = since.map(|t| format!("since {t}\n")).unwrap_or_default();
    let lines: String = header
        + &tasks
            .iter()
            .map(|(tid, s)| format!("{tid} {} {}\n", s.start, s.old))
            .collect::<String>();
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

/// The slack that the threads of each process that has a task in @tracked
/// had before, the one of its lowest thread id if there are several. Tasks
/// that are gone or replaced are not in it.
fn slack_sources(tracked: &BTreeMap<i32, Saved>) -> BTreeMap<i32, u64> {
    let mut sources = BTreeMap::new();
    for (tid, saved) in tracked {
        if task_stat(*tid).is_some_and(|(start, _)| start == saved.start)
            && let Some((tgid, _)) = task_status(*tid)
        {
            sources.entry(tgid).or_insert(saved.old);
        }
    }
    sources
}

/// The slack a thread of process @tgid most likely inherited: the one of a
/// task of @tgid in @sources, else of the closest ancestor process that has
/// one, as told by @parent, else DEFAULT_SLACK.
fn inherited_slack(
    tgid: i32,
    sources: &BTreeMap<i32, u64>,
    parent: impl Fn(i32) -> Option<i32>,
) -> u64 {
    let mut pid = tgid;
    for _ in 0..=MAX_ANCESTORS {
        if let Some(old) = sources.get(&pid) {
            return *old;
        }
        match parent(pid) {
            Some(ppid) if ppid > 0 => pid = ppid,
            _ => break,
        }
    }
    DEFAULT_SLACK
}

/// Write the slack of @sources back to the SCHED_NORMAL threads that started
/// at @since or later, have one nanosecond and are not in @tracked, which
/// are the ones that inherited it. Returns how many were written. Threads
/// that cannot be read, as when they exit meanwhile, are skipped.
fn restore_inherited(
    since: u64,
    tracked: &BTreeMap<i32, Saved>,
    sources: &BTreeMap<i32, u64>,
) -> usize {
    let Ok(procs) = fs::read_dir("/proc") else {
        return 0;
    };
    let id = |entry: fs::DirEntry| entry.file_name().to_str()?.parse::<i32>().ok();
    let mut seen = 0;
    let mut restored = 0;
    for pid in procs.flatten().filter_map(id) {
        let Ok(threads) = fs::read_dir(format!("/proc/{pid}/task")) else {
            continue;
        };
        let mut old = None;
        for tid in threads.flatten().filter_map(id) {
            seen += 1;
            if seen > MAX_SCAN {
                return restored;
            }
            if read_slack(tid) != Some(CRITICAL_SLACK) {
                continue;
            }
            let Some((start, policy)) = task_stat(tid) else {
                continue;
            };
            if start < since
                || policy != SCHED_NORMAL
                || tracked.get(&tid).is_some_and(|s| s.start == start)
            {
                continue;
            }
            let old = *old.get_or_insert_with(|| {
                inherited_slack(pid, sources, |p| task_status(p).map(|(_, ppid)| ppid))
            });
            if fs::write(slack_path(tid), old.to_string()).is_ok() {
                restored += 1;
            }
        }
    }
    restored
}

/// Write back the slack of @tracked, then, if @since is known, of the
/// threads that inherited it. Returns how many were written.
fn restore_all(tracked: &BTreeMap<i32, Saved>, since: Option<u64>) -> usize {
    let sources = slack_sources(tracked);
    let direct = tracked.iter().filter(|(tid, s)| restore(**tid, s)).count();
    direct + since.map_or(0, |t| restore_inherited(t, tracked, &sources))
}

/// Write back the slack that a scheduler which was killed left behind. A
/// task that is gone, or that is not the one the line was written for, is
/// skipped, so the file is always removed after.
pub fn restore_saved_slack() {
    let Ok(saved) = fs::read_to_string(SAVED_SLACK) else {
        return;
    };
    let state = parse_saved(&saved);
    let tracked = state.tasks.into_iter().collect();
    let restored = restore_all(&tracked, state.since);
    if restored > 0 {
        info!("restored the timer slack of {restored} tasks left behind by an earlier run");
    }
    forget_saved();
}

/// The latency critical tasks of --lowlatency get the smallest timer slack,
/// see the module comment. The old slack is written back when dropped.
pub struct TimerSlack {
    tasks: BTreeMap<i32, Saved>,
    /// When the first slack was lowered, as boot_ticks().
    since: Option<u64>,
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
            since: None,
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
        if self.since.is_none() {
            self.since = boot_ticks();
        }
        if let Err(e) = save(self.since, &self.tasks) {
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
        restore_all(&self.tasks, self.since);
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

    fn saved(start: u64, old: u64) -> Saved {
        Saved { start, old }
    }

    #[test]
    fn saved_lines() {
        let text = "12 345 50000\n13 346 1000 7\nx 1 2\n14 347\n15 348 200\n";
        assert_eq!(
            parse_saved(text),
            SavedState {
                since: None,
                tasks: vec![(12, saved(345, 50000)), (15, saved(348, 200))],
            }
        );
    }

    #[test]
    fn saved_since() {
        let text = "since 9000\n12 345 50000\nsince 1\n13 346 200\n";
        assert_eq!(
            parse_saved(text),
            SavedState {
                since: Some(9000),
                tasks: vec![(12, saved(345, 50000)), (13, saved(346, 200))],
            }
        );
        assert_eq!(parse_saved("since x\nsince 5\n").since, Some(5));
        assert_eq!(parse_saved("since 5 6\n12 1 2\n").since, None);
        assert_eq!(parse_saved("since\n").tasks, []);
        assert_eq!(parse_saved(""), SavedState::default());
    }

    #[test]
    fn status_fields() {
        let status = "Name:\tfoo\nTgid:\t4242\nNgid:\t0\nPid:\t4243\nPPid:\t17\n";
        assert_eq!(parse_status(status), Some((4242, 17)));
        assert_eq!(parse_status("Tgid:\t4242\n"), None);
        assert_eq!(parse_status("Tgid:\tx\nPPid:\t1\n"), None);
    }

    #[test]
    fn uptime_ticks() {
        assert_eq!(parse_uptime("12345.67 9876.54\n"), Some(1234567));
        assert_eq!(parse_uptime("0.05 1.00\n"), Some(5));
        assert_eq!(parse_uptime("7.5 1.00\n"), Some(750));
        assert_eq!(parse_uptime("7.123456 1.00\n"), Some(712));
        assert_eq!(parse_uptime("7 1.00\n"), None);
        assert_eq!(parse_uptime(""), None);
    }

    #[test]
    fn inherited_source() {
        // 10 is init's child, 20 a shell under it, 30 a browser under the
        // shell, and 40 a content process under the browser.
        let parents: BTreeMap<i32, i32> = [(10, 1), (20, 10), (30, 20), (40, 30), (50, 1)].into();
        let parent = |pid: i32| parents.get(&pid).copied();
        let sources: BTreeMap<i32, u64> = [(30, 4000), (20, 3000)].into();

        // The same process comes first.
        assert_eq!(inherited_slack(30, &sources, parent), 4000);
        // Then the closest ancestor with a task of its own.
        assert_eq!(inherited_slack(40, &sources, parent), 4000);
        assert_eq!(inherited_slack(20, &sources, parent), 3000);
        // Nothing above: the default of init.
        assert_eq!(inherited_slack(10, &sources, parent), DEFAULT_SLACK);
        assert_eq!(inherited_slack(50, &sources, parent), DEFAULT_SLACK);
        // A process that is not known, or has no parent left to look at.
        assert_eq!(inherited_slack(99, &sources, parent), DEFAULT_SLACK);
        assert_eq!(inherited_slack(40, &BTreeMap::new(), parent), DEFAULT_SLACK);
    }

    #[test]
    fn inherited_source_loop() {
        // A parent chain that does not end must not hang.
        let sources: BTreeMap<i32, u64> = BTreeMap::new();
        assert_eq!(
            inherited_slack(5, &sources, |pid| Some(if pid == 5 { 6 } else { 5 })),
            DEFAULT_SLACK
        );
    }
}
