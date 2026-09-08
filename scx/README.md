# scx_flow

scx_flow is a user-defined scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps two tiers. New tasks start in tier zero. The
slices are fixed per tier. It is deliberately knob-free.

## Overview

Tasks wait in two tiers, plus one park DSQ for tasks
with no allowed CPU. Tier zero is interactive with a
five hundred microsecond slice. Tier one is batch with
an eight millisecond slice ordered by vruntime. New
tasks start in tier zero. Each tier keeps its own
waiting count. A runnable task that burns the full
slice moves down one tier at once. Blocked tasks build
a streak of short bursts below one millisecond. Three
short blocks in a row move up one tier, with the streak
capped at seven. Dispatch serves tier zero eight times
per tier one serve when both tiers hold work. Idle
targets are kicked at once. A narrow busy preemption
covers tier zero wakeups against tier one runners with
a per CPU rate gate. Tier zero wakeups join at the head
and requeues join at the tail. Tier one joins by
vruntime with new tasks at the floor.

The tier math and the move rules live in
`src/bpf/intf.h`, insert, accounting, dispatch and the
ops table in `src/bpf/main.bpf.c`, the Rust mirrors
with unit tests in `src/flow.rs`, and constant
validation in `src/config.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Ops name is `flow` with 30000 ms watchdog.

## Typical Use Cases

- Gaming and other latency-sensitive applications.
  Short bursts start in tier zero with five hundred
  microsecond slices and drain first, so wakeups and
  frame work rarely wait behind batch work.
- General desktop use. The session stays responsive
  while long bursts move toward tier one and serve
  eight millisecond slices without competing with
  interactive tasks.
- Mixed batch workloads. Long jobs keep throughput
  with vruntime order while short arrivals keep
  draining through tier zero.

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
for demotion, promotion streak, burn boundary, vruntime
order, FIFO order, deficit, preempt gap, tier math and
config checks.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line, two tier rows with per tier slices and
waiting counts and a per CPU grid with running
estimates and running tier badges, with no
authentication, since the loopback address is the trust
boundary. `--no-webui` disables it. Empty states show
an idle tier line and a no CPU data card when no data
has arrived.

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

- Idle wakeup kick. Wakeups join tier zero at the head
  and kick an idle target to collect at once.
- Tiers share the machine. Idle CPUs collect batch
  work through the deficit gate only when the head may
  run on the idle CPU.
- The topology is snapshotted at attach, so a CPU
  hotplug needs a restart.
- Unknown frequency stays unknown. Hosts that report
  zero show freq unknown on the dashboard and in the
  start log, with no effect on placement.
- Machines with one thread per core run plain per CPU
  with no sibling step and no SMT badge. A single CPU
  host runs with no peer scan through the same gates.
- sched_ext cannot schedule RT and DL tasks. The
  kernel resolves them to the rt and dl classes before
  sched_ext, so this scheduler handles SCHED_NORMAL,
  SCHED_BATCH and SCHED_IDLE tasks only.
- Needs a kernel with sched_ext enabled.

## Tiers

Tier zero is interactive. Tier one is batch. The batch
DSQ uses id `0x2000` and the park DSQ uses id `0x2001`.
One park DSQ holds tasks with no allowed CPU.

## Slices

Tier zero serves five hundred microseconds. Tier one
serves eight milliseconds. Each grant is fixed at
insert time and stored for the burn check. Per task
estimates hold the last burst clamped at one nanosecond
to one second with no smoothing. New batch tasks join
at the vruntime floor. Running batch tasks advance by
the burst with saturation.

## Insert and dispatch

Enqueue keeps tier zero in per CPU local DSQs and tier
one in the shared DSQ. New tasks start in tier zero.
Each new insert joins the target tier count. A runnable
requeue keeps the count and may move tiers on burn, so
no double count occurs. Running keeps the entry.
Blocking releases it at once. Disable and exit release
exactly once. A full slice burn with the task runnable
moves down one tier. Three short blocks below one
millisecond move up one tier. Enqueue keys the CPU off
the selected CPU, then the first allowed CPU. Pinned
tasks use their CPU or the park. Tasks that cannot
move stay on the current CPU. Dispatch serves the
batch DSQ through the eight to one deficit gate. Each
pass moves a batch task only when the head may run on
the asking CPU, plus park tasks whose head may run on
the asking CPU. Each pass tries once with no spin. An
idle kick is sent only to a CPU in the task mask. A
busy preemption is sent only for tier zero wakeups
against tier one runners inside the per CPU gap and
only to a CPU in the wakee mask.

## Cpu choice

Cpu choice prefers an idle CPU in the task mask, then
the prior CPU when allowed, then the current CPU when
allowed, then the first allowed CPU. Pinned tasks stay
in place. Tasks that cannot move stay on the current
CPU. Idle choice is rechecked in the mask. A final
hint without an allowed CPU falls back to the park in
enqueue. Enqueue reuses the selected CPU when allowed,
then the first allowed CPU, then the park. Tasks that
cannot move use the local DSQ. The path uses only
public helpers with version gates where needed.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover inserts per tier, moves down and
up, runs per tier, gated batch serves, idle kicks,
busy preemptions and inserts without state.
Deficit serves count batch moves in dispatch. Kicks
count idle wakeup kicks. Preempts count busy
preemptions for batch runners.
