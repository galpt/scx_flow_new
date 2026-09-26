# scx_flow

scx_flow is our own deadline scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one shallow FIFO plus one deadline queue per CPU,
one shared overflow tail, and the kernel global queue. Slices
are dynamic from weight and pressure with no knob. Only
`SCHED_OTHER` tasks may use the fast lane.

## Overview

### Queues

Tasks rest in a per CPU fast FIFO at base `0x6000` plus id
with depth `4`, a per CPU deadline queue at `0x6800` plus id,
one shared overflow tail at `0x7000`, and the kernel global
queue. Max `2049` DSQs at `1024` CPUs. Every id stays below
`LOCAL_ON`, and init fails loudly past the bound. Pinned and
foreign tasks rest in overflow with mask wins on drain.
Homeless tasks rest in the global queue with mask wins on
drain, and the drain counts the global moves. Exiting tasks
run at once on the task CPU via `LOCAL_ON`.
See `src/bpf/intf.h` and `src/bpf/enqueue.bpf.c`.

### Dynamic slices

Slices span `250us` to `15ms` with a `5ms` target and a
`500us` micro quantum. The bound is the larger of the target
and depth times the minimum, shared by weight over pressure,
then clamped to the bounds. Base weight `100` holds the
target alone, range `1` to `10000`. Each lane sizes from its
own queued depth plus one with one probe, so the fast lane
skips the deadline probe and the lag cap divide. See
`src/bpf/intf.h` and `src/flow_slice.rs`.

### Admission

Duty tracks intensity with alpha `1/8` over each stop. Sleep
decays it, short bursts climb gently with a `1.5ms` allowance,
and long runs climb hard. Only duty under `15` percent, or a
voluntary wake, may use the fast lane past two probation
wakes. Fresh tasks anchor at the minimum minus lag cap and
never take the fast lane early. See `src/bpf/enqueue.bpf.c`
and `src/flow_admit.rs`.

### Ledger

Every segment charges weight scaled time to virtual time, fast
lane or not. Each CPU keeps a high water minimum that never
moves back. Entries clamp to the larger of task time and
minimum minus lag cap, where lag is `5ms` times base over
weight. The deadline is the clamped time, carried as DSQ
vtime. Steals add a scaled `500us` penalty with no knob to
turn it off. See `src/bpf/lifecycle.bpf.c`.

### Preemption

Interactive tasks preempt batch owners prompt at a `100us`
floor, one kick per `2ms` window per CPU. The window gates
before occupant resolution, and one trusted lookup serves
class plus slice shorten under one RCU pass. Interactive
pairs yield at the micro quantum end with no kick. Batch
pairs kick only past slice exhaust with a deadline gap over
one quantum. Batch never preempts interactive, and pinned
arrivals never preempt a busy CPU. No timer kick runs, so
the floor is a slice shorten plus kick approximation. See
`src/bpf/enqueue.bpf.c` and `src/flow_preempt.rs`.

### Priority help

Voluntary sleep records a waiter per CPU. A wake inside `1ms`
elevates the running occupant once with a `500us` slice
override and a fast head insert at its next enqueue. Release
or expiry demotes with no rearm. The owner is unobservable
without extra kfuncs, so the running occupant is the proxy.
See `src/bpf/lifecycle.bpf.c` and `src/bpf/enqueue.bpf.c`.

### Placement

Order is waker CPU when idle and allowed, any idle via
`pick_idle`, prior when allowed, then first allowed, and the
task mask always wins. Pinned tasks keep the task CPU when
allowed, else the selected CPU, else the first allowed CPU.
Pinned means migration disabled or one CPU allowed. Empty
masks rest in the global queue. Frequency cards stay display
only and never shape placement. No frequency write runs in
`4.4.0`, and the governor stays free. A running-only boost
contract stays deferred: it needs the study plus hot path
budget proof, and responsiveness wins over knob writes
until then. See `src/bpf/select_cpu.bpf.c`
and `src/bpf/enqueue.bpf.c`.

### Dispatch

Order is own fast at `4`, own deadline at `12`, one peer
steal with a single move, global plus overflow at `4`, then a
gated starvation pass, toward budget `32`. All trips skip
empty with one read, so idle pays no empty scan. One shared
drain moves mask allowed tasks to local with a miss cap at
`4`, so one bad head never blocks later work with no full
scan. See `src/bpf/dispatch.bpf.c`, `src/bpf/intf.h`, and
`src/flow_slot.rs`.

### Steal

Steal never visits a peer fast queue, so sleepy tasks stay
local. The SMT sibling wins first, then the same cache
domain over bound `8` with a prandom salt and a cursor step
of `8`. Need is `1` when idle and empty else `2`. The gated
cross domain pass moves only tasks waiting past `1.5ms` from
donors holding at least two. Single CPU hosts skip the pass.
See `src/bpf/dispatch.bpf.c` and `src/flow_select.rs`.

### Kicks

Idle targets kick at once with the idle flag cleared first,
so no idle CPU with queued work sleeps unkicked. Busy kicks
follow the class rules with the rate window. A null or self
occupant keeps kick only with no shorten. Fallback global
with no live CPU sends no kick and the next drain pass
collects it with mask wins. Exiting uses an idle kick on the
task CPU. See `src/bpf/intf.h`, `src/bpf/main.bpf.c`, and
`src/bpf/enqueue.bpf.c`.

### Accounting

Running sets the running pid and counts on CPU. Stopping
charges one scaled segment to total runtime and the ledger,
steps duty, keeps the minimum high water, and counts one
requeue per runnable stop else one completion. Disable and
exit charge a leftover segment at most once when stopping
never ran. Release clears a stale running view with no
charge and drops the waiter window. See
`src/bpf/lifecycle.bpf.c` and `src/bpf/main.bpf.c`.

### Counters

Counters stay at `160B` with `20` u64 fields. Fields are
`on_cpu`, `total_runtime`, `inserts`, `requeues`,
`completions`, `park_moves`, `steal_moves`, `kicks`,
`enq_no_tctx`, `preempt_kicks`, `preempt_skipped`,
`slot_moves`, `fast_admits`, `fast_bounds`, `vtime_admits`,
`duty_gates`, `prob_holds`, `elev_moves`, `steal_penalties`,
and `global_moves`. The dashboard JSON carries the same
fields with per CPU `running_pid`, dynamic `slice_ns`, and
`min_vruntime`. Old JSON still decodes with defaults. See
`src/stats.rs` and `src/snapshot.rs`.

### A and B validation

The deadline queue is an ordered DSQ with `O(log n)`
insert, so tail claims need measurement, not code reading.
The A/B signals are `fast_admits`, `vtime_admits`,
`duty_gates`, `prob_holds`, `preempt_kicks`, and
`preempt_skipped` via `--monitor` and the dashboard.
Request tail comes from the harness probe delay plus
`schbench` percentiles on the same host, governor, and
seeds. Take at least 3 repeats per build before calling a
change neutral or better. The wakeup path stays lean with
per-lane sizing, rate first kicks, and one trusted occupant
lookup, so instrumentation never taxes it. See
`tools/edf_harness/README.md`.

## Typical Use Cases

- Latency-sensitive applications. Sleepy wakeups land in a
  shallow local FIFO with capped drains, so they rarely wait
  behind long work.
- General desktop use. The session stays responsive while
  long bursts serve with weight sized slices without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput through
  deadline order plus steal while short arrivals keep the
  fast lane.

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
It shows move rates, preempt rates, admission gauges,
per CPU running pids with dynamic slice and minimum, and a
button to download the full snapshot as JSON. Energy stays
display only. `--no-webui` disables it.

## Code map

- Queue rules: `src/bpf/intf.h`
- Maps, helpers, ops table: `src/bpf/main.bpf.c`
- Placement: `src/bpf/select_cpu.bpf.c`
- Inserts: `src/bpf/enqueue.bpf.c`
- Drains: `src/bpf/dispatch.bpf.c`
- Lifecycle: `src/bpf/lifecycle.bpf.c`
- Rust mirrors: `src/flow_slice.rs`, `src/flow_edf.rs`,
  `src/flow_admit.rs`, `src/flow_select.rs`,
  `src/flow_preempt.rs`, `src/flow_slot.rs`
- Facade: `src/flow.rs`
- Tests: inline `tests` modules in each mirror
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

- CPU live means below the `nr` snapshot at attach with no
  kernel online read. A CPU hotplug needs a restart, and no
  live rebalance runs. Select may still target an offlined
  CPU, and its fast FIFO strands until restart since steal
  never visits fast queues. Its deadline work stays
  stealable, and homeless tasks fail closed to the global
  queue with mask wins on drain. Snapshot covers online
  only with per CPU count matching online count.
- Release `4.4.0` needs a scheduler restart from `4.3.x`
  with no live transition. Queues are fast at `0x6000` plus
  id with depth `4`, deadline at `0x6800` plus id, and
  overflow at `0x7000`. Task state is `40B`, CPU state is
  `16B`, and counters are `160B` with `20` fields. Busy rate
  stays `2ms`. Dashboard JSON changed with the same field
  names kept where live.
- Unknown frequency stays unknown with no effect on
  placement. Frequency, slice, minimum, and energy cards are
  display only.
- Single-thread and single-CPU hosts run the same path
  with no peer scan.
- Needs a kernel with sched_ext enabled, `7.2` series and
  up. Compat guards keep older kfuncs working where present.
