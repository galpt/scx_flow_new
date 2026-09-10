# scx_flow

scx_flow is our own EDF scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one ordered queue per-CPU with a fixed slice at
1ms. It is deliberately knob-free. It uses per-CPU ordered
EDF plus vruntime fairness plus the fixed slice.

## Overview

Tasks wait in per-CPU ordered queues, plus one park queue for
tasks with no allowed CPU. Queues hold EDF order first with
arrival order for ties. The deadline adds clamped virtual time
and scaled estimate with a fixed weight of 1024. The kernel queue orders by deadline with the slice as the
slice. The slice is fixed at 1ms with no knob.
Fresh tasks join with the slice, so the start stays neutral.
Estimates hold the last burst clamped at 1ns to 1 second.
Sleeper lag is capped at one slice behind the
frontier, so a waking task gains at most one slice of advantage
with wrap safe order. Virtual time moves forward by scaled
runtime and the frontier moves forward while work stays queued.
An idle reset bounds to waking virtual time with no zero use.
Blocked tasks complete at once. Runnable tasks requeue ordered
with a refreshed estimate. Placement uses any idle CPU in the
mask, then the prior CPU, the current CPU, and the first allowed
CPU. Pinned tasks and tasks that cannot move stay local. Empty
masks park in order. Frequency plus LLC plus CPU cards stay
display only and never shape placement.
Pinned subsets such as Lestat 16 plus 16 stay in mask.
Single-CPU Konaka never leaves. Mask respect keeps every
choice inside the task mask.
Dispatch drains the local queue first, then the park queue, then
idle steals from peers. Each pass visits every queued task in the
local and park queues in order and moves live tasks
when allowed, including exiting tasks so they run to exit,
and skips past dead, foreign and failed heads, so every pass moves
at least one task when movable work exists there. An idle CPU with
no moved work steals past unmovable leftovers, while a busy CPU
with moved work steals only when both queues are empty. Idle steals
scan past bad heads to rescue movable work when the donor holds at
least two tasks. Idle targets are kicked only when the queue was
empty with a mask check and no busy preemption.

The slice math and the queue rules live in
`src/bpf/intf.h`, insert, accounting, dispatch and the
ops table in `src/bpf/main.bpf.c`, the Rust mirrors
in `src/flow_mean.rs` plus `src/flow_edf.rs` plus
`src/flow_select.rs` with a thin facade in `src/flow.rs`
and tests only in `src/flow_tests_edf.rs`, and constant
validation in `src/config.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Ops name is `flow` with a 30 second watchdog. Version
is `4.2.7` in 4.2 line. Weight stays 1024 with no
knob. The slice stays fixed at 1ms.
Task state stays at 32B. Per-CPU state stays at 24B.
Counters stay at 96B. The `4.2.6` base is the last stable
line. The `4.3.x` plus `4.4.0` lines were tried and failed
with stalls and were abandoned. The `4.2.7` strip keeps a
pure EDF core with the fixed slice.

## Typical Use Cases

- Latency-sensitive applications. Short deadlines run first,
  so wakeups and frame work rarely wait behind long work.
- General desktop use. The session stays responsive
  while long bursts serve with a fixed slice without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput
  with ordered queues while short arrivals keep draining
  first.

## Production Ready?

Yes.

## Configuration

The scheduler is deliberately knob-free. The
scheduling constants are compile-time values in
`src/bpf/intf.h`, and no command-line option changes
the scheduling behavior. The runtime footprint depends
only on the reporting options, which are `--stats`,
`--monitor` and `--no-webui`. See `src/config.rs` and
`src/flow.rs` for the checked values and the unit tests
for slice fixed, estimate clamp, EDF order, sleeper cap,
frontier order, ordered inserts, progress guarantee, steal
bounds, donor depth, kick check, mask respect, display only
cards and config checks. For A/B comparison, install one build,
measure the same workload, then install the other build and
compare with no other change.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line and a per-CPU grid with running estimates
and fixed slices, plus system tiles for
EDF enqueued, EDF clamped and EDF ordered, with no
authentication, since the loopback address is the trust
boundary.
`--no-webui` disables it. Empty states show an empty CPU
data card when no data has arrived.

## Queues

Each CPU keeps one ordered queue. Per-CPU queues use ids
`0x4000` plus the CPU id with up to 1024 CPUs. One park queue
uses id `0x5000` and holds tasks with no allowed CPU.

## Slices

Each CPU serves a fixed slice at 1ms. Per task
estimates hold the last burst clamped at 1ns
to 1 second. Fresh tasks join with the
slice, so the start stays neutral. Sleeper lag is capped
at one slice behind the frontier with wrap safe order.

## Insert and dispatch

Enqueue places each task on the selected CPU when allowed,
then the first allowed CPU, then the park. Pinned
tasks use their CPU or the park. Tasks that cannot
move stay on the current CPU. Each insert computes the
frontier and the slice, clamps virtual time to at most
one slice behind the frontier with wrap safety, scales
the estimate with a fixed weight of 1024, and stores the
deadline for the kernel queue with the slice as the slice.
Running keeps the entry. Blocking completes it at once.
Disable and exit count one completion. Dispatch drains the
local queue first, then the park queue, then idle steals
from peers. Each pass moves up to 32 tasks across local,
park and steal. Each move in the local and park queues moves
live tasks when allowed, including exiting
tasks so they run to exit, and skips dead, foreign and failed
tasks, so one head never blocks later work there. Steals take
the first task in a peer queue that allows the thief when the
donor holds at least two tasks and move past bad heads to rescue
movable work behind them. An idle CPU with no moved work steals
past unmovable leftovers, while a busy CPU with moved work
steals only when both queues are empty. An idle kick is
sent only when the queue was empty to a CPU in the task
mask with no busy preemption.

## CPU choice

CPU choice prefers an idle CPU in the task mask, then the
prior CPU when allowed, then the current CPU when allowed,
then the first allowed CPU. Pinned tasks stay in place. Tasks
that cannot move stay on the current CPU. Frequency plus LLC
plus CPU cards stay display only and never shape placement.
Idle
choice is rechecked in the mask. A final choice
without an allowed CPU falls back to the park in
enqueue. Enqueue reuses the selected CPU when
allowed, then the first allowed CPU, then the park.
Tasks that cannot move use the per-CPU queue. The path
uses only public helpers.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover inserts, requeues, completions,
park moves, steal moves, idle kicks, inserts without
state, EDF enqueued, EDF clamped and EDF ordered. Park moves
count dispatch moves from the park queue. Steal moves count
dispatch moves from peer queues. Kicks count idle wakeup
kicks sent only when the queue was empty. EDF
enqueued counts deadline inserts. EDF clamped counts sleeper
caps to one slice. EDF ordered counts kernel queue inserts
in order.

## Measuring Wakeup Latency

To measure the wakeup latency the scheduler delivers
with cyclictest, pin the measurement threads to
dedicated CPUs with `-a`, use the monotonic clock
(`-c 0`), and the performance governor, and move the
device IRQs off the measured CPUs. For percentiles, run
schbench with two message threads (`-m 2`) on an otherwise
quiet machine. The harness probe wakes each 10ms and records
wake delay as a light baseline with no realtime use.

## Limitations

- Idle wakeup kick. Wakeups join in EDF order and kick an
  idle target only when the queue was empty to collect
  at once.
- Queues stay per-CPU. Idle CPUs collect park work and
steal peer work with a scan past bad heads when the
donor holds at least two tasks, so movable work behind
a dead, foreign or failed head is rescued when the task
allows the idle CPU.
- The topology is snapshotted at attach, so a CPU
  hotplug needs a restart.
- Unknown frequency stays unknown. Hosts that report
  zero show freq unknown on the dashboard and in the
  start log, with no effect on placement. Frequency plus
  LLC plus CPU cards stay display only and never shape
  placement.
- Machines with one thread per core run plain per-CPU
with no sibling step and no SMT badge. A single CPU
  host runs with no peer scan through the same path.
- Needs a kernel with sched_ext enabled.
