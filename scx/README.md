# scx_flow

scx_flow is our own slot scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps 512 FIFO slot queues sharded by two groups
with one overflow tail per group and a fixed slice at
1ms. Two groups split light waits and hog burn, strict
exactly when ready is zero and best effort when ready
is one.
It is deliberately knob-free. It uses deadline mapped
FIFO slots, vruntime fairness, and the fixed slice.

## Overview

### Order and deadlines

Tasks wait in FIFO slot buckets picked by deadline,
with one overflow tail per group for far deadlines.
Pinned tasks rest in the group overflow tail with no
bucket use, so every owner dispatch visits them in the
window. A probe maps the deadline to a near slot near
64us or pins past the horizon to the tail, so arrival
order holds inside each queue. The deadline adds
clamped virtual time and a scaled estimate at live
weight from nice. Exiting tasks run at once on the
task CPU via LOCAL_ON with no order wait. The task
CPU wins over the enqueuer, so an exit enqueued
elsewhere still runs where the task lives. Single
insert with an idle kick only and no coalesce. Falls
back when the task CPU is not allowed.

### Fixed slice

The slice is fixed at 1ms with no knob. Fresh tasks join
with the slice, so the start stays neutral. Estimates hold
the last burst clamped at 1ns to 1 second.

### Fairness

Sleeper lag is capped at a weight scaled cap in 125us to
8ms, so a waking task gains at most the cap of advantage.
Virtual time moves forward with scaled runtime while work
stays queued and resets to waking time on idle. Blocked
tasks complete at once. Runnable tasks requeue FIFO
into the probed bucket with a refreshed estimate. Burst
allowance reads windowed depths over own cursor, two
fill, rescue, and both overflows with six reads, so
quiet keeps 4ms and flood still floors at 1ms with no
514 scan. Marks cover head and fine only with far blocks
in overflow, so one insert pays two atomics.

### Groups

Two groups split physical cores with siblings kept in one
group and cache local shares where the hardware allows.
All singleton cores use halves exactly, so dense full
keeps prior state. Online ranks seed by id with offline
light inert, skewed forces ready one, snapshot covers
online only. Strict when ready is zero, best effort when
ready is one.

### Placement

Strict order is waker CPU when idle in group,
free core in group, any idle in group, prior,
current, then first allowed in group, then first
allowed, and the task mask always wins. First
allowed keeps lowest id with group overflow depth
as the group backlog. Perf widens each miss to any
allowed, see governor mode. An idle core cannot
stack, so locality is free. Every other case keeps
current behavior. Pinned tasks stay local. Empty masks
rest in the task group overflow tail in arrival order.
Frequency cards stay display only and never shape
placement. Pinned subsets stay in mask. Groups seed
by online rank with write by id. See
`src/bpf/select_cpu.bpf.c` and `src/bpf/enqueue.bpf.c`.

### Dispatch

Strict order is own cursor bucket at 31, group overflow at 4, two fill ahead at 4 each, other group overflow at 4, then the other group cursor at 1 when it holds work. Overflow trips skip empty with one read and no iterator, so light pays no empty scan. One rescue suffices because rotation and the kick sweep cover every bucket, so cross-group rescue stays an exception path. The other overflow trip keeps a hog far tail drainable on an all-light host with mask wins. Pinned tasks rest in overflow, so trips visit them every pass with no rotation. Rotation advances the cursor each dispatch with capped retain at most 3 in a row, so every occupied bucket drains within 1024 dispatches with refill to zero on advance. Idle adds a far sweep to the next own bucket ahead with queued work when own holds no work, so boot 15 and 61 drain within 3 hops. Hint checks the last near insert first with one read, window gate skips the 256 scan when overflow, fill, rescue, or other overflow holds work, else the full scan runs. Far runs only when own holds no work, so hot pays no scan with no storm. Bound is 256 hops worst case with one far kick on any move while far jumps. Own at 31 leaves one slot for the rest, so saturated own still lets overflow, fill, other overflow, and rescue progress. A capped drain with window work left counts one defer with no kick. A kick safety net chains idle owners past the watchdog with far kicks on any move when idle jumps far and sweep kicks at 256 on zero-move window truth only with no storm. Moves with window but no far ride the next natural dispatch with no kick, since the loop already visited every task and the CPU runs the moved work before the next pass. All trips share one drain body with mask wins and move to local, so per queue order stays FIFO. Placement, dispatch, and pressure read the live table. See `src/bpf/dispatch.bpf.c`, `src/bpf/intf.h`, and `src/flow_slot.rs`.

### Kicks

Idle targets are always kicked with a mask check
regardless of shared queue depth, so no idle CPU with
queued work sleeps unkicked. Busy targets stay
fail-closed with no preempt and one armed skip count,
since the sharded store keeps no per CPU depth for a
deserved compare. The gate keeps total and five reason
counters with branch order armed, deserved, group,
mask, and rate, so busy no-kicks count under armed
only in the slot store. One coalesced count covers q2 idle
skips in 50us at 288B. Second queued to idle in 50us
skips when not pinned with no slide, single queued
always kicks, deep always kicks, pinned never skips.
Delay persists across idle, delay shows stale
when idle. A missed wakeup is rescued on the next
insert with no strand. Exiting uses
a separate idle kick on the task CPU with no depth,
no coalesce, and no preempt. Fallback overflow with
no live CPU sends no kick and the next rotation or
rescue pass collects it. Pinned overflow from a live
owner keeps the normal idle kick with no coalesce.
Disarmed stays idle only. See `src/bpf/intf.h`,
`src/bpf/main.bpf.c`, `src/bpf/enqueue.bpf.c`, and
`src/flow_select.rs`.

### Governor mode

Strict keeps group isolation with mask win.
Perf widens placement to any allowed on miss
with same tier order and least over group overflow.
Perf bypasses the kick group gate with no recount,
so group skips stay flat in perf. Unanimous
performance over online CPUs sets perf one,
else strict zero. Polls online only on the 1s tick
with BSS write on transition only. Dashboard shows
strict and perf in the mode cell with governor tip.
Dispatch reads live groups with no perf widen.
No CLI knob changes this. See `src/bpf/intf.h`,
`src/bpf/select_cpu.bpf.c`, and `src/bpf/enqueue.bpf.c`.
See `src/topology.rs`, `src/snapshot.rs`, and `ui/index.html`.

### CPU perf

Running maps the stored EMA to 0 to 1024
uniform both groups with no tier. Stopping
decays by elapsed with 24ms half-life then
climbs on the burst toward the 1ms budget
with 12x in FP8, so boost follows load with
fast attack and slow decay. Blocked with
empty queues maps the decayed EMA, long sleep
with no burst still maps to zero via 64
period decay. Init and no state hold max
1024. See `src/bpf/intf.h`,
`src/bpf/lifecycle.bpf.c`, and `src/bpf/main.bpf.c`.

Weight follows nice from minus 20 to 19 with center 1024
and no knob. The slice stays fixed at 1ms. The version is
in `Cargo.toml`.

### Energy probe

Package energy comes from RAPL counters with per-CPU active time from BPF
state. The probe alternates strict and baseline arms and reports collecting,
waiting, and unavailable states until enough accepted pairs exist for a
headline. Daily, yearly, and since attach savings appear in kWh on the
dashboard with a live trace. Details live in `src/rapl.rs`,
`src/snapshot.rs`, and `src/stats.rs`. See `src/webui.rs`,
`ui/index.html`, and `src/bpf/intf.h` for the full path.

## Typical Use Cases

- Latency-sensitive applications. Near deadlines land in near slots with
  capped per bucket drains, so wakeups and frame work rarely wait behind
  long work at one head.
- General desktop use. The session stays responsive
  while long bursts serve with a fixed slice without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput
  with FIFO slots while short arrivals keep draining
  through rotation.

## Production Ready?

Yes.

## Configuration

The scheduler is knob-free. No command-line option changes
scheduling behavior. Reporting only is `--stats`,
`--monitor` and `--no-webui`.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock` and no
authentication, since loopback is the trust boundary.
It shows group depths, move rates, preempt rates, slot moves with defer and
safety net kicks,
per-CPU nice, weight, and delay dots, and a button
to download the full snapshot as JSON.
`--no-webui` disables it.

## Code map

- Slice math and queue rules: `src/bpf/intf.h`
- Maps, helpers, ops table: `src/bpf/main.bpf.c`
- Placement: `src/bpf/select_cpu.bpf.c`
- Inserts: `src/bpf/enqueue.bpf.c`
- Drains: `src/bpf/dispatch.bpf.c`
- Lifecycle and classifier: `src/bpf/lifecycle.bpf.c`
- Rust mirrors: `src/flow_slice.rs`, `src/flow_edf.rs`,
  `src/flow_select.rs`, `src/flow_group.rs`,
  `src/flow_preempt.rs`, `src/flow_slot.rs`
- Facade: `src/flow.rs`
- Tests: `src/flow_tests_edf.rs`,
  `src/flow_tests_group.rs`, `src/flow_tests_preempt.rs`,
  `src/flow_tests_slot.rs`
- Constant validation: `src/config.rs`
- Generated bindings and skeleton: `src/bpf_intf.rs`,
  `src/bpf_skel.rs`
- Snapshot and topology: `src/snapshot.rs`,
  `src/topology.rs`
- Stats and dashboard payload: `src/stats.rs`,
  `src/webui.rs`, `ui/index.html`

## Measuring Wakeup Latency

Pin measurement threads to dedicated CPUs, use the
monotonic clock and the performance governor, and move
device IRQs off the measured CPUs. The harness probe
wakes each 10ms and records wake delay as a light
baseline with no realtime use.

## Limitations

- Groups are strict when ready is zero and best effort
  when ready is one. Placement, dispatch, and pressure read the live table
  seeded by online rank with offline light inert. Rescue is mask only across
  groups.
- Topology with online set is snapshotted at attach, so
  a CPU hotplug needs a restart. Snapshot covers online
  only with per CPU count matching online count.
- Unknown frequency stays unknown with no effect on
  placement. Frequency cards are display only.
- Single-thread and single-CPU hosts run the same path
  with no peer scan.
- Light load probe delay rises +163 to +223 percent in
  relative terms while absolute delay stays sub-ms, so the
  gap reads as a slot path tradeoff with no hot miss. See
  `src/bpf/dispatch.bpf.c` and `src/flow_slot.rs`.
- Needs a kernel with sched_ext enabled.
