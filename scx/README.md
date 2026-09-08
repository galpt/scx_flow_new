# scx_flow

Flow is a three level feedback scheduler for the kernel
sched_ext feature. Enqueue picks a level from the live
means. Unknown estimates start at the top. Known estimates
use the first level with a mean at or above the estimate.
Large estimates fall to the bottom. Tasks move down one
level each time they consume a full slice. There is no
move up. The shape stays small and the path stays plain.

## Levels and queues

Each cpu owns three queues, one per level. Queue ids use
base `0x1000` plus cpu times three plus level, so the cpu
and the level decode with plain math. Level zero holds
short interactive work. Level one holds middle work.
Level two holds long work.

## Quanta

Level means seed at one, two and eight milliseconds. Each
level keeps a live mean from queued estimates. The mean
is the sum over the count clamped to five hundred
microseconds and thirty two milliseconds. Updates are
incremental with saturation. An empty level keeps the
last mean. Per task estimates clamp at one nanosecond
to one second. Each grant clamps to the same quantum
range.

## Insert and dispatch

Enqueue picks a level from the estimate. Unknown goes to
the top. Known uses the first level with a live mean at
or above the estimate. Large falls to the bottom. Inserts
use the tail, so each queue stays first in first out. Each
insert adds the clamped estimate to the level sum. Each
consume removes it with compare and swap and saturation.
A demote moves the entry between levels. Dispatch drains
the local queues top down. Each level drains fully before
the next one with no level cap. Steal scans level major
with sixty four checks in total. The top uses twenty two
checks and the others use twenty one each. Steal moves a
task only when the head may run on the stealing cpu. Each
pass moves up to thirty two tasks in batch. A consumed
slice moves the task down one level. No kick is sent on
wakeup.

## Cpu choice

Cpu choice prefers an idle cpu in the task mask, then the
prior cpu when allowed, then the current cpu when allowed,
then the first allowed cpu. Pinned tasks stay in place.
Idle choice is rechecked in the mask. A final hint without
an allowed cpu is left for the kernel. The path uses only
public helpers with version gates where needed.

## Ops

Ops name is `flow`. The watchdog is thirty thousand
milliseconds. Flags honor exiting tasks, the last enqueue
hint, migration disabled tasks and queued wakeups.

## Config

The scheduler ships without knobs. Constants validate at
start. See `src/config.rs` and `src/flow.rs` for the
checked values and the unit tests for estimate choice,
top down drain, steal split, affinity guard, quantum
clamp, queue math and config checks.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock`. It shows a
summary line, the live per level means and a per cpu grid.
Use `--no-webui` to disable it.

## Stats

`--stats` prints deltas. `--monitor` runs the printer
only. Counters cover per level inserts, moves down,
remote moves, local and remote moves and inserts without
state. Dispatches count local and remote moves. Steals
count remote moves only.

## Limits

- No move up. Long tasks settle at the bottom.
- No preempt kick. Wakeups join the queue tail.
- Queues are per cpu. Idle cpus pull remote work only
  when the head may run on the idle cpu.
- Topology reads once at attach. Hotplug needs restart.
- Needs a kernel with sched_ext enabled.

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
