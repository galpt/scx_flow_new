# scx_flow

scx_flow is a user-defined scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one ordered queue per cpu. Tasks order by
estimated burst with the shortest first. The slice
follows a global live mean. It is deliberately knob-free.

## Breaking note in 4.0.0

Version stays at `4.0.0` by user decision, but this
release breaks prior behavior. The prior three queues
per cpu are now one ordered queue per cpu with stride
one. The prior per level placements and demotions are
now placements and requeues. The prior per level means
and depths are now a single live mean, a total queued
count, per cpu depths and head and tail ages. Per cpu
cards now carry a running estimate with no level. Old
stat readers and old dashboards need an update.

## Overview

Tasks wait in one per cpu ordered queue, plus a global
park for tasks with no allowed cpu. The global mean
covers all accounted tasks, seeded at two milliseconds
and clamped to five hundred microseconds and thirty two
milliseconds. Inserts order by estimate only. Unknown
estimates start at the front and known estimates sort
ascending. Equal keys keep insert order. The slice
follows the live mean only. A runnable requeue refreshes
the sum and reinserts in order. Queues drain in order.
Dispatch drains the local queue in a batch of thirty
two. Idle cpus pull remote work in one scan of sixty
four checks with affinity checked steals. There is no
move down step and no wakeup preemption.

The queue math and the key rule live in
`src/bpf/intf.h`, insert, accounting, dispatch and the
ops table in `src/bpf/main.bpf.c`, the Rust mirrors
with unit tests in `src/flow.rs`, and constant
validation in `src/config.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Ops name is `flow` with 30000 ms watchdog.

## Typical Use Cases

- Gaming and other latency-sensitive applications.
  Short bursts sort near the front with about two
  millisecond slices and drain first, so wakeups and
  frame work rarely wait behind batch work.
- General desktop use. The session stays responsive
  while long bursts sort toward the back and serve
  bounded slices without competing with interactive
  tasks.
- Mixed batch workloads. Long jobs keep throughput
  with the shared mean while short arrivals keep
  draining through the front.

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
for key order, tie stability, unknown front, slice
separation, refresh balance, release safety, depth
balance, steal guard, quantum clamp, queue math and
config checks.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line, the single queue meter with live mean and
total queued, head and tail ages and a per cpu grid with
running estimates, with no authentication, since the
loopback address is the trust boundary. `--no-webui`
disables it. Empty states show an idle queue line and a
no cpu data card when no data has arrived.

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

- No preempt kick. Wakeups join the queue in order.
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

Each cpu owns one ordered queue. Queue ids use base
`0x1000` plus cpu with stride one, so the cpu decodes
with plain math. The global park holds tasks with no
allowed cpu.

## Quanta

The global mean seeds at two milliseconds. The mean is
the sum over the count clamped to five hundred
microseconds and thirty two milliseconds. Updates are
incremental with saturation. An empty set keeps the last
mean. Per task estimates clamp at one nanosecond to one
second. Each grant clamps to the same quantum range and
follows the live mean only.

## Insert and dispatch

Enqueue orders by estimate only. Unknown maps to key
zero and sorts at the front. Known maps to the clamped
estimate and sorts ascending. Equal keys keep insert
order. Each new insert adds the clamped estimate to the
sum. A runnable requeue refreshes the sum only, so no
double count occurs. Running keeps the entry. Blocking
releases it with compare and swap and saturation.
Dequeue, disable and exit release exactly once. Enqueue
keys the queue off the selected cpu, then the first
allowed cpu. Pinned tasks use their cpu or the global
park. Dispatch drains the local queue in order. Steal
scans in one pass of sixty four checks with rotation.
Steal moves a task only when the head may run on the
stealing cpu. Each pass moves up to thirty two tasks in
batch. A runnable task reinserts in order. No kick is
sent on wakeup.

## Cpu choice

Cpu choice prefers an idle cpu in the task mask, then
the prior cpu when allowed, then the current cpu when
allowed, then the first allowed cpu. Pinned tasks stay
in place. Idle choice is rechecked in the mask. A
final hint without an allowed cpu is left for the
kernel. Enqueue reuses the selected cpu when allowed,
then the first allowed cpu, then the global park. The
path uses only public helpers with version gates where
needed.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover placements, requeues, remote
moves, local and remote moves and inserts without
state. Dispatches count local and remote moves. Steals
count remote moves only.
