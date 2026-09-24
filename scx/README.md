# scx_flow

scx_flow is our own slot scheduler for Linux, written
in Rust with a BPF core, that runs inside
[`sched_ext`](https://github.com/sched-ext/scx/tree/main).
It keeps one bounded LIFO queue per CPU plus one overflow
tail, with a fixed slice at 1ms. It is deliberately knob-free.
Queue order is bounded LIFO at K 3 with no virtual time use.

## Overview

### Order

Tasks wait in per CPU queues at base `0x6000` plus id with
one shared overflow tail at `0x6800`. Max `1025` DSQs at
`1024` CPUs. Inserts take head for `3` of `9` with six tails
per period plus one forced tail at `MAX`. At most `3`
consecutive head inserts per queue. Overflow and steal keep
at least one slot per pass. This is a consecutive insert
bound with no wait time bound. One atomic add claims one
period slot with no scan, so enqueue stays `O(1)`. Head use
is user DSQ only. Pinned tasks rest in the overflow tail with
no per CPU use, so every owner dispatch visits them in the
window. Exiting tasks run at once on the task CPU via
`LOCAL_ON` with no queue wait. The task CPU wins over the
enqueuer. Empty masks rest in the overflow tail in queue order.
See `src/bpf/intf.h` and `src/bpf/enqueue.bpf.c`.

### Fixed slice

The slice is fixed at 1ms with no knob. Fresh tasks join
with the slice, so the start stays neutral.

### Placement

Order is waker CPU when idle and allowed, any idle via
`pick_idle`, prior when allowed, then first allowed, and the
task mask always wins. Pinned tasks keep the task CPU when
allowed, else the selected CPU, else the first allowed CPU.
Pinned means migration disabled or one CPU allowed. Empty
masks rest in the overflow tail. Frequency cards stay display
only and never shape placement. See `src/bpf/select_cpu.bpf.c`
and `src/bpf/enqueue.bpf.c`.

### Dispatch

Order is own queue at `12`, overflow at `4`, then one peer
steal with a single move toward budget `32`. All trips skip
empty with one read, so idle pays no empty scan. One shared
drain moves mask allowed tasks to local with a miss cap at
`4`, so one bad head never blocks later work with no full
scan. Overflow shares the same miss cap with no head stall.
The steal scan visits bound `8` peers from start with wrap
plus live check and keeps the first donor at need, which is
`1` when idle with no moves and no window work, else `2`.
The cursor steps by `8` with wrap so passes spread with no
hotspot. Single CPU hosts skip the pass. Pinned tasks rest
in overflow, so trips visit them each pass. All trips share
one `__noinline` drain with mask wins and move to local, so
order stays bounded LIFO at K `3`. See `src/bpf/dispatch.bpf.c`,
`src/bpf/intf.h`, and `src/flow_slot.rs`.

### Kicks

Idle targets are always kicked with a mask check regardless
of queue depth, so no idle CPU with queued work sleeps
unkicked. Busy targets kick at most once per `2ms` window
with soft preempt. Pinned tasks never preempt a busy CPU.
A null or self occupant keeps kick only with no shorten,
else the occupant slice shortens to zero so the kick sticks.
Fallback overflow with no live CPU sends no kick and the next
drain pass collects it with mask wins. Exiting uses an idle
kick on the task CPU with no depth and no preempt. See
`src/bpf/intf.h`, `src/bpf/main.bpf.c`, and
`src/bpf/enqueue.bpf.c`.

### Accounting

Running sets the running pid and counts on CPU. Stopping
charges one segment to total runtime, clears the running pid,
and counts requeue or completion. Virtual time and frontier
keep one max with no queue read. Placement, dispatch, and
kicks never read them, so they stay accounting only with no
scheduling use. Disable and exit charge a leftover segment at
most once when stopping never ran. Release clears a stale
running view with no charge. See `src/bpf/lifecycle.bpf.c`
and `src/bpf/main.bpf.c`.

### Counters

Counters stay at `112B` with `14` u64 fields. Fields are
`on_cpu`, `total_runtime`, `inserts`, `requeues`,
`completions`, `park_moves`, `steal_moves`, `kicks`,
`enq_no_tctx`, `preempt_kicks`, `preempt_skipped`,
`slot_moves`, `lifo_heads`, and `lifo_bound_hits`. The
dashboard JSON carries the same fields with per CPU
`running_pid` and fixed `slice_ns`. Upgrading from `4.2.46`
changes queue ids, LIFO, caps, rate, and JSON, so it needs
a scheduler restart with no live transition. See `src/stats.rs`
and `src/snapshot.rs`.

## Typical Use Cases

- Latency-sensitive applications. Near arrivals land at head
  with capped trip drains, so wakeups rarely wait behind
  long work at one head.
- General desktop use. The session stays responsive
  while long bursts serve with a fixed slice without blocking
  short arrivals.
- Mixed batch workloads. Long jobs keep throughput
  with bounded LIFO at K `3` while short arrivals keep draining
  through trips plus steal.

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
It shows move rates, preempt rates, slot moves,
per CPU running pids with fixed slice, and a button
to download the full snapshot as JSON.
`--no-webui` disables it.

## Code map

- Queue rules: `src/bpf/intf.h`
- Maps, helpers, ops table: `src/bpf/main.bpf.c`
- Placement: `src/bpf/select_cpu.bpf.c`
- Inserts: `src/bpf/enqueue.bpf.c`
- Drains: `src/bpf/dispatch.bpf.c`
- Lifecycle: `src/bpf/lifecycle.bpf.c`
- Rust mirrors: `src/flow_slice.rs`, `src/flow_edf.rs`,
  `src/flow_select.rs`, `src/flow_preempt.rs`, `src/flow_slot.rs`
- Facade: `src/flow.rs`
- Tests: `src/flow_tests_edf.rs`,
  `src/flow_tests_preempt.rs`,
  `src/flow_tests_slot.rs`, `src/flow_tests_lifo.rs`
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
  kernel online read. A CPU hotplug needs a restart. Unknown
  CPUs fail closed to overflow with mask wins on drain.
  Offline queues drain via overflow plus steal on the next
  pass until restart. Snapshot covers online only with per
  CPU count matching online count.
- Release `4.3.0` needs a scheduler restart from `4.2.46`
  with no live transition. Queue ids are `0x6000` plus id
  with overflow at `0x6800`. LIFO moved `K 8` to `K 3` with
  `3` heads per `9`. Own cap moved `31` to `12` with miss
  `8` to `4`. Busy rate moved `1ms` to `2ms`. Dashboard JSON
  changed with the same `112B` and `14` counters.
- Unknown frequency stays unknown with no effect on
  placement. Frequency cards are display only.
- Single-thread and single-CPU hosts run the same path
  with no peer scan.
- Needs a kernel with sched_ext enabled.
