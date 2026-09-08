# scx_flow

scx_flow is a user-defined scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one ordered queue per CPU with a per-CPU mean slice.
It is deliberately knob-free.

## Overview

Tasks wait in per-CPU ordered queues, plus one park queue for
tasks with no allowed CPU. Queues hold short estimates first
with arrival order for ties. The per-CPU mean is the sum over
unfinished work divided by the count with the running task
included. The seed is 8ms with a floor of 500µs and a ceiling
of 32ms. Fresh tasks join with the current mean so the mean
stays neutral. Estimates hold the last burst clamped at 1ns
to 1 second with no smoothing. Blocked tasks complete and release
at once. Runnable tasks requeue ordered with a refreshed
estimate. Dispatch drains the local queue first, then the park
queue, then idle steals from peers. Each pass visits every
queued task in the owned and park queues in order and moves
live tasks with no move failure when allowed, including
exiting tasks so they run to exit, and skips past dead,
foreign and failed heads, so every pass moves at least one
task when movable work exists there. An idle CPU with no
moved work steals past unmovable leftovers, while a busy CPU
with moved work steals only when both queues are empty. Idle
steals scan past bad heads to rescue movable work. Idle
targets are kicked at once with a mask check and no busy preemption.

The mean math and the queue rules live in
`src/bpf/intf.h`, insert, accounting, dispatch and the
ops table in `src/bpf/main.bpf.c`, the Rust mirrors
with unit tests in `src/flow.rs`, and constant
validation in `src/config.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Ops name is `flow` with a 30 second watchdog.

## Typical Use Cases

- Gaming and other latency-sensitive applications.
  Short bursts run first with small means, so wakeups and
  frame work rarely wait behind long work.
- General desktop use. The session stays responsive
  while long bursts serve larger means without blocking
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
for mean range, fresh neutral joins, estimate clamp,
ordered inserts, progress guarantee, steal bounds, LLC
choice and config checks.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line and a per-CPU grid with running estimates,
per-CPU means and per-CPU depths, with no
authentication, since the loopback address is the trust
boundary. `--no-webui` disables it. Empty states show
an empty CPU data card when no data has arrived.

## Queues

Each CPU keeps one ordered queue. Per-CPU queues use ids
`0x4000` plus the CPU id with up to 1024 CPUs. One park queue
uses id `0x5000` and holds tasks with no allowed CPU.

## Slices

Each CPU serves its mean. The seed is 8ms. The floor is
500µs. The ceiling is 32ms. Each grant is fixed at
insert time and stores the mean. Per task
estimates hold the last burst clamped at 1ns
to 1 second with no smoothing. Fresh tasks join
with the current mean, so the mean stays neutral.

## Insert and dispatch

Enqueue places each task on the selected CPU when allowed,
then the first allowed CPU, then the park. Pinned
tasks use their CPU or the park. Tasks that cannot
move stay on the current CPU. Each fresh join adds the
estimate to the target mean. Each runnable requeue refreshes
the estimate in the mean with no count change. Running keeps
the entry. Blocking releases it at once. Disable and exit
release exactly once. Dispatch drains the local queue first,
then the park queue, then idle steals from peers. Each
pass moves up to 32 tasks across local, park and steal. Each
move in the local and park queues moves live tasks with no
move failure when allowed, including exiting tasks so they
run to exit, and skips dead, foreign and failed tasks, so one
head never blocks later work there. Steals take the first
task in a peer queue that allows the thief and move past bad
heads to rescue movable work behind them. An idle CPU with
no moved work steals past unmovable leftovers, while a busy
CPU with moved work steals only when both queues are empty. An
idle kick is sent only to a CPU in the task mask with no
busy preemption.

## CPU choice

CPU choice prefers an idle CPU in the previous CPU
LLC domain, then an idle CPU in the task mask, then
the prior CPU when allowed, then the current CPU
when allowed, then the first allowed CPU. Pinned
tasks stay in place. Tasks that cannot move stay on
the current CPU. The LLC step skips the second
thread of a busy core and is skipped on single LLC
and unknown topology hosts, which stay plain. Idle
choice is rechecked in the mask. A final hint
without an allowed CPU falls back to the park in
enqueue. Enqueue reuses the selected CPU when
allowed, then the first allowed CPU, then the park.
Tasks that cannot move use the per-CPU queue. The path
uses only public helpers with version gates where
needed.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover inserts, requeues, completions,
park moves, steal moves, idle kicks and inserts without
state. Park moves count dispatch moves from the park queue.
Steal moves count dispatch moves from peer queues. Kicks
count idle wakeup kicks.

## Measuring Wakeup Latency

To measure the wakeup latency the scheduler delivers
with cyclictest, pin the measurement threads to
dedicated CPUs with `-a`, use the monotonic clock
(`-c 0`), a realtime priority (`-p 99`), and the
performance governor, and move the device IRQs off the
measured CPUs. For percentiles, run schbench with two
message threads (`-m 2`) on an otherwise quiet
machine.

## Limitations

- Idle wakeup kick. Wakeups join ordered and kick an
  idle target to collect at once.
- Queues stay per-CPU. Idle CPUs collect park work and
  steal peer work with a scan past bad heads, so movable
  work behind a dead, foreign or failed head is rescued
  when the task allows the idle CPU.
- The topology is snapshotted at attach, so a CPU
  hotplug needs a restart.
- Unknown frequency stays unknown. Hosts that report
  zero show freq unknown on the dashboard and in the
  start log, with no effect on placement.
- Machines with one thread per core run plain per-CPU
  with no sibling step and no SMT badge. A single CPU
  host runs with no peer scan through the same gates.
- Needs a kernel with sched_ext enabled.
