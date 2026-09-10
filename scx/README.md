# scx_flow

scx_flow is our own EDF scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one ordered queue per-CPU with a fixed slice at
1ms plus two groups for light waits and hog burn, strict
iff ready is zero and best effort iff ready is one.
It is deliberately knob-free. It uses per-CPU ordered
EDF plus vruntime fairness plus the fixed slice.

## Overview

### Order and deadlines

Tasks wait in per-CPU ordered queues, plus one park queue
per group for tasks with no allowed CPU. Earliest deadline
runs first with arrival order for ties. The deadline adds
clamped virtual time and a scaled estimate at fixed weight.

### Fixed slice

The slice is fixed at 1ms with no knob. Fresh tasks join
with the slice, so the start stays neutral. Estimates hold
the last burst clamped at 1ns to 1 second.

### Fairness

Sleeper lag is capped at one slice behind the frontier,
so a waking task gains at most one slice of advantage.
Virtual time moves forward with scaled runtime while work
stays queued and resets to waking time on idle. Blocked
tasks complete at once. Runnable tasks requeue ordered
with a refreshed estimate.

### Groups

Two groups split physical cores with siblings kept in one
group and cache local shares where the hardware allows.
All singleton cores use halves exactly, so SMT off keeps
prior state. Strict when ready is zero, best effort when
ready is one.

### Placement

Order is free core in group, any idle in group, prior,
current, then first allowed, and the task mask always
wins. Pinned tasks stay local. Empty masks park in order
in the task group. Frequency cards stay display only and
never shape placement. Pinned subsets stay in mask.

### Dispatch

Order is local queue, group park, then steals from idle
peers with mask checks. An idle thief may rescue a lone
queued task while busy thieves keep depth 2. Isolation
follows placement plus park choice with peer best effort
across groups.

### Kicks

Idle targets are kicked even with queued work with a mask
check and no busy preemption. Park sends no kick and the
next dispatch pass collects it.

The slice math and the queue rules live in
`src/bpf/intf.h`, maps plus helpers plus the ops table in
`src/bpf/main.bpf.c`, placement in
`src/bpf/select_cpu.bpf.c`, inserts in
`src/bpf/enqueue.bpf.c`, drains in
`src/bpf/dispatch.bpf.c`, and lifecycle plus classifier in
`src/bpf/lifecycle.bpf.c`, the Rust mirrors
in `src/flow_slice.rs` plus `src/flow_edf.rs` plus
`src/flow_select.rs` plus `src/flow_group.rs` with a thin
facade in `src/flow.rs`
and tests for S1 to S3 plus slice, estimate, EDF order,
frontier, dispatch, steal, mask, groups, classifier,
and config in
`src/flow_tests_edf.rs` plus `src/flow_tests_group.rs`,
constant validation in
`src/config.rs`, generated bindings in `src/bpf_intf.rs`
plus the generated skeleton in `src/bpf_skel.rs`, and
snapshot plus topology in `src/snapshot.rs` plus
`src/topology.rs`. Stats and the dashboard
payload live in `src/stats.rs`, `src/webui.rs` and
`ui/index.html`.

Weight stays 1024 with no knob. The slice stays fixed
at 1ms. The current version is `4.2.10`.

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

Yes iff ready is zero. Hosts with ready is one get best
effort grouping, see Limitations.

## Configuration

The scheduler is knob-free. No command-line option changes
scheduling behavior. Reporting only is `--stats`,
`--monitor` and `--no-webui`.

## Web UI

The dashboard serves loopback port `50005` with a unix
socket fallback at `/tmp/scx_flow.sock` and no
authentication, since loopback is the trust boundary.
It shows group depths, move rates, per-CPU state, and a
button to download the full snapshot as JSON.
`--no-webui` disables it.

## Code map

Slice math and queue rules are in `src/bpf/intf.h`,
maps plus helpers plus the ops table in
`src/bpf/main.bpf.c`, placement in
`src/bpf/select_cpu.bpf.c`, inserts in
`src/bpf/enqueue.bpf.c`, drains in
`src/bpf/dispatch.bpf.c`, lifecycle plus classifier in
`src/bpf/lifecycle.bpf.c`. Rust mirrors are in
`src/flow_slice.rs`, `src/flow_edf.rs`,
`src/flow_select.rs` and `src/flow_group.rs` with tests
in `src/flow_tests_edf.rs` plus
`src/flow_tests_group.rs`. Stats plus payload are in
`src/stats.rs`, `src/webui.rs` and `ui/index.html`.

## Measuring Wakeup Latency

Pin measurement threads to dedicated CPUs, use the
monotonic clock and the performance governor, and move
device IRQs off the measured CPUs. The harness probe
wakes each 10ms and records wake delay as a light
baseline with no realtime use.

## Limitations

- Groups are strict when ready is zero and best effort
  when ready is one. Dispatch uses halves while placement
  uses the live table. Peer steal is mask only.
- Topology is snapshotted at attach, so a CPU hotplug
  needs a restart.
- Unknown frequency stays unknown with no effect on
  placement. Frequency cards are display only.
- Single-thread and single-CPU hosts run the same path
  with no peer scan.
- Needs a kernel with sched_ext enabled.
