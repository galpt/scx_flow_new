# scx_flow

scx_flow is a user-defined scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It is a three-level feedback queue that follows the
optimum multilevel paper. Each level keeps a live mean
burst quantum, tasks enter by estimated burst with the
shortest first, tasks that fit the quantum run to
completion and tasks that burn it move down one level.
It is deliberately knob-free.

## Overview

Tasks are placed into three per-CPU levels, L0 for
short bursts, L1 for middle bursts and L2 for long
bursts. Each level keeps a live mean quantum from the
estimated remainders of its queued tasks, seeded at 1,
2 and 8 ms and clamped to 500 us and 32 ms. Enqueue
picks the first level whose mean covers the estimate.
Unknown estimates start at the top and large estimates
fall to the bottom. Queues run first in first out.
Dispatch drains the local queues top down with no
level cap inside a batch of 32. A task that burns its
full slice moves down one level. There is no move up
and no wakeup preemption. Idle CPUs pull remote work
level major with affinity-checked steals.

The level math and the pick rule live in
`src/bpf/intf.h`, insert, accounting, dispatch and the
ops table in `src/bpf/main.bpf.c`, the Rust mirrors
with unit tests in `src/flow.rs`, and constant
validation in `src/config.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

## Typical Use Cases

- Gaming and other latency-sensitive applications.
  Short bursts stay in L0 with about 1 ms quanta and
  drain first, so wakeups and frame work rarely wait
  behind batch work.
- General desktop use. The session stays responsive
  while CPU hogs sink to L2 and serve larger slices
  without competing with interactive tasks.
- Mixed batch workloads. Long jobs keep throughput
  with larger means while short arrivals keep draining
  through the top.

## Production Ready?

Yes.

## Configuration

The scheduler is deliberately knob-free. The
scheduling constants are compile-time values in
`src/bpf/intf.h`, and no command-line option changes
the scheduling behavior. The runtime footprint depends
only on the reporting options, which are `--stats`,
`--monitor` and `--no-webui`.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line, the live per level means and a per cpu
grid, with no authentication, since the loopback
address is the trust boundary. `--no-webui` disables
it.

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

- No move up. Long tasks settle at the bottom and
  progress through bounded quanta.
- No preempt kick. Wakeups join the queue tail.
- Queues are per cpu. Idle cpus pull remote work only
  when the head may run on the idle cpu.
- The topology is snapshotted at attach, so a CPU
  hotplug needs a restart.
- sched_ext cannot schedule RT and DL tasks. The
  kernel resolves them to the rt and dl classes before
  sched_ext, so this scheduler handles SCHED_NORMAL,
  SCHED_BATCH and SCHED_IDLE tasks only.
- Needs a kernel with sched_ext enabled.

## Levels and queues

Each cpu owns three queues, one per level. Queue ids
use base `0x1000` plus cpu times three plus level, so
the cpu and the level decode with plain math. Level
zero holds short interactive work. Level one holds
middle work. Level two holds long work.

## Quanta

Level means seed at one, two and eight milliseconds.
Each level keeps a live mean from queued estimates.
The mean is the sum over the count clamped to five
hundred microseconds and thirty two milliseconds.
Updates are incremental with saturation. An empty
level keeps the last mean. Per task estimates clamp
at one nanosecond to one second. Each grant clamps to
the same quantum range.

## Insert and dispatch

Enqueue picks a level from the estimate. Unknown goes
to the top. Known uses the first level with a live
mean at or above the estimate. Large falls to the
bottom. Inserts use the tail, so each queue stays
first in first out. Each insert adds the clamped
estimate to the level sum. Each consume removes it
with compare and swap and saturation. A demote moves
the entry between levels. Dispatch drains the local
queues top down. Each level drains fully before the
next one with no level cap. Steal scans level major
with sixty four checks in total. The top uses twenty
two checks and the others use twenty one each. Steal
moves a task only when the head may run on the
stealing cpu. Each pass moves up to thirty two tasks
in batch. A consumed slice moves the task down one
level. No kick is sent on wakeup.

## Cpu choice

Cpu choice prefers an idle cpu in the task mask, then
the prior cpu when allowed, then the current cpu when
allowed, then the first allowed cpu. Pinned tasks stay
in place. Idle choice is rechecked in the mask. A
final hint without an allowed cpu is left for the
kernel. The path uses only public helpers with version
gates where needed.

## Ops

Ops name is `flow`. The watchdog is thirty thousand
milliseconds. Flags honor exiting tasks, the last
enqueue hint, migration disabled tasks and queued
wakeups.

## Config

The scheduler ships without knobs. Constants validate
at start. See `src/config.rs` and `src/flow.rs` for
the checked values and the unit tests for estimate
choice, top down drain, steal split, affinity guard,
quantum clamp, queue math and config checks.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover per level inserts, moves down,
remote moves, local and remote moves and inserts
without state. Dispatches count local and remote
moves. Steals count remote moves only.

## Build

This dir overlays into a workspace at
`scheds/experimental/scx_flow` and builds there with
path deps at `../../../rust`. See the root readme and
`tools/install_scx_flow.sh` for the steps.

## Verification

fmt is clean, 45 tests pass, debug and release builds
succeed, and veristat reports 12 of 12 success.
Workspace-wide clippy with -D warnings currently fails
in upstream crates under rustc 1.98.1 and clippy 0.1.98
with no diagnostics in this package. Package-scoped
fmt, clippy, test, and build gates for this package are
green.
