# scx_flow

scx_flow is a user-defined scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps three queues per cpu. New tasks start in queue
zero. The slice follows a per queue live mean. It is
deliberately knob-free.

## Overview

Tasks wait in three per cpu queues, plus one park queue
per queue index for tasks with no allowed cpu. Each
queue keeps its own mean. Queue zero seeds at one
millisecond and clamps to five hundred microseconds and
four milliseconds. Queue one seeds at two milliseconds
and clamps to one millisecond and eight milliseconds.
Queue two seeds at eight milliseconds and clamps to
four milliseconds and thirty two milliseconds. Each
queue keeps FIFO order. New tasks start in queue zero.
A runnable task that burns the full slice moves down
one queue. Blocked tasks and short runs hold the queue.
A head age past five hundred milliseconds lifts the
queue past strict order and moves the task up one
queue. Dispatch moves up to thirty two tasks in strict
queue order with the age override. Idle cpus pull
remote work in one scan of sixty four checks with
affinity checked steals. There is no wakeup kick.

The queue math and the move rules live in
`src/bpf/intf.h`, insert, accounting, dispatch and the
ops table in `src/bpf/main.bpf.c`, the Rust mirrors
with unit tests in `src/flow.rs`, and constant
validation in `src/config.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Ops name is `flow` with 30000 ms watchdog.

## Typical Use Cases

- Gaming and other latency-sensitive applications.
  Short bursts start in queue zero with about one
  millisecond slices and drain first, so wakeups and
  frame work rarely wait behind batch work.
- General desktop use. The session stays responsive
  while long bursts move toward queue two and serve
  bounded slices without competing with interactive
  tasks.
- Mixed batch workloads. Long jobs keep throughput
  with the per queue means while short arrivals keep
  draining through queue zero.

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
for demotion, promotion age boundary, FIFO order,
starvation fairness, refresh balance, release safety,
depth balance, steal guard, quantum clamp, queue math
and config checks.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line, three queue meters with per queue quanta
and queued counts and head ages and a per cpu grid with
running estimates and running queue index, with no
authentication, since the loopback address is the trust
boundary. `--no-webui` disables it. Empty states show
an idle queue line and a no cpu data card when no data
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

- No wakeup kick. Wakeups join the queue in FIFO order.
- Queues are per cpu. Idle cpus pull remote work only
  when the head may run on the idle cpu.
- The topology is snapshotted at attach, so a CPU
  hotplug needs a restart.
- sched_ext cannot schedule RT and DL tasks. The
  kernel resolves them to the rt and dl classes before
  sched_ext, so this scheduler handles SCHED_NORMAL,
  SCHED_BATCH and SCHED_IDLE tasks only.
- Needs a kernel with sched_ext enabled.

## Queues

Each cpu owns three queues. Queue ids use base
`0x1000` plus cpu times three plus queue index, so the
cpu and the queue decode with plain math. One park
queue per queue index holds tasks with no allowed cpu.

## Quanta

Queue zero seeds at one millisecond. The mean is the
sum over the count clamped to five hundred microseconds
and four milliseconds. Queue one seeds at two
milliseconds and clamps to one millisecond and eight
milliseconds. Queue two seeds at eight milliseconds and
clamps to four milliseconds and thirty two milliseconds.
Updates are incremental with saturation. An empty queue
keeps the last mean. Per task estimates hold the last
burst clamped at one nanosecond to one second with no
smoothing. Each grant clamps to the queue range and
follows the live mean of the target queue.

## Insert and dispatch

Enqueue keeps FIFO order in each queue. New tasks start
in queue zero. Each new insert adds the clamped estimate
to the target queue sum. A runnable requeue refreshes
the sum when the queue holds and moves the sum when the
queue changes, so no double count occurs. Running keeps
the entry. Blocking releases it with compare and swap
and saturation. Dequeue, disable and exit release
exactly once. A full slice burn with the task runnable
moves down one queue. A head age past five hundred
milliseconds moves up one queue. Enqueue keys the cpu
off the selected cpu, then the first allowed cpu.
Pinned tasks use their cpu or the park. Dispatch drains
the local queues in strict queue order with the age
override. Steal scans in one pass of sixty four checks
with rotation. Steal moves a task only when the head
may run on the stealing cpu. Each pass moves up to
thirty two tasks in batch. No kick is sent on wakeup.

## Cpu choice

Cpu choice prefers an idle cpu in the task mask, then
the prior cpu when allowed, then the current cpu when
allowed, then the first allowed cpu. Pinned tasks stay
in place. Idle choice is rechecked in the mask. A
final hint without an allowed cpu is left for the
kernel. Enqueue reuses the selected cpu when allowed,
then the first allowed cpu, then the park. The path
uses only public helpers with version gates where
needed.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover placements per queue, moves down
per queue, moves up per queue, requeues, remote moves,
local and remote moves and inserts without state.
Dispatches count local and remote moves. Steals count
remote moves only.
