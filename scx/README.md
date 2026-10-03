# scx_flow

### What is it?

scx_flow runs the fairest task first by virtual time. It keeps fair order in kernel priority queues with vruntime plus a burst predictor from recent runs. The core joins every waiting task with no bound and a fixed `1ms` slice for steady pacing under load today. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Why?

The goal is to test fair order with prediction in the kernel and see if short bursts reach a CPU sooner. Finding the earliest fair time without a full scan matters when order decides who runs next. Direct queue order keeps the test fair and repeatable. See `src/bpf/intf.h` and `src/bpf/enqueue.bpf.c`.

### How it works?

Arrivals always pass a gate first. Tasks earn EDF deadlines from the predictor else the hint period plus virtual deadlines from vruntime plus slice over weight. Each CPU takes the earliest fair time it may run. Teardown charges plus advances vruntime with predictor update always. See `src/bpf/enqueue.bpf.c`, `src/bpf/dispatch.bpf.c` and `src/rust/flow/edf.rs`.

## Typical Use Cases

- Latency sensitive apps. Tasks with the earliest fair time run first, so short arrivals never wait behind long work and stay responsive under load.
- Desktop use. A `1ms` slice keeps interaction smooth while background work continues, so typing stays fluid with no extra tuning.
- Mixed batch work. Fair order keeps overload feasible, so heavy jobs still finish while urgent tasks move ahead in turn.

## More details

### Queues

One local queue per CPU plus one per node plus machine hold tasks across 521 queues. Each pass drains local plus node plus machine in fair order with at most one move per tier bounded by remaining slots and visits capped at 64 with resume. No queue waits with no scan. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Each fair time orders as priority value with vruntime pacing via lag bounds. Predictor average plus deviation shapes deadlines with shift updates plus quarter floor. Virtual deadline adds slice over weight with shifts and no divide. Fair key holds deadline plus virtual deadline with 2ms clamp. See `src/bpf/intf.h` and `src/rust/flow/edf.rs`.

### Admission

Tasks carry weight with default 128 and every join counts one admit with no reject. Hint period plus weight bands shape deadline while predictor shapes deadlines only. Rejects stay zero for wire compat with rejects in gate_rejects. Misses count due on blocking ends with effort drain. See `src/bpf/enqueue.bpf.c` and `src/rust/flow/edf.rs`.

### Gates

A gate runs first at each step so tasks and CPUs wait safely. Exiting work runs at once. Fails drop the ledger with no leak. Drain stays affinity gated with mask wins. Eligibility gates every kick, so hogs pace while lagging tasks wake. One counter tracks held work. See `src/bpf/main/cpu.bpf.c`.

### Reporting

Flags `--stats`, `--monitor` and `--no-webui` show counters as text or on a page at `50005`. Page keeps local, node, machine, kicks apart with no overflow. Snapshots share one moment for review with times plus minima. Dashboard shows thirteen counters plus uptime with per CPU cards. See `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Changes live in `CHANGELOG.md` with the `4.7.4` shape.
- Live kernel logic lives in `src/bpf/main.bpf.c` with parts in `src/bpf/main/`, `src/bpf/dispatch.bpf.c`, `src/bpf/dispatch/`, `src/bpf/enqueue.bpf.c`, `src/bpf/enqueue/`, `src/bpf/lifecycle.bpf.c`, `src/bpf/cgroup.bpf.c`, `src/bpf/select_cpu.bpf.c` and `src/bpf/helpers/`. No `fair.c` helper is used and the queue order stays in kernel priority queues.
- Order lives in kernel priority queues with mirrors in `src/rust/flow/edf.rs`, `src/rust/flow/slot.rs`, `src/rust/flow/select.rs`, `src/rust/flow/preempt.rs`, `src/rust/flow/slice.rs` and `src/rust/flow/cgrp.rs` for tests only. The mirrors check fair order plus vruntime plus saturation against the kernel logic, since no kernel test harness runs here.
- Deadline plus fair checks live in `src/bpf/main/deadline.bpf.c` with a mirror in `src/rust/flow/edf.rs` for tests only. The mirror keeps the same hint plus predictor plus vruntime math with no effect on order.
- Task vruntime bookkeeping lives in `src/rust/flow/edf.rs` with the slice plus scaler in `src/rust/flow/slice.rs` plus placement in `src/rust/flow/select.rs` plus kicks in `src/rust/flow/preempt.rs` plus checks in `src/rust/config.rs`.
- Speed levels live in `src/bpf/dispatch/perf.bpf.c` and run once per dispatch pass.
- Dashboard lives in `src/rust/snapshot.rs`, `src/rust/topology.rs`, `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`. Snapshots merge core admits, rejects, misses as source of truth.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `64B`, `16B`, `8B`, `104B`.
- Needs kernels, `7.2` series and up.
- Priority queues never mix orders, since the kernel keeps one fair key per queue and a mix fails closed with an error.
- Mask wins on drain, since affinity gates every move with priority tiers skipping to the next match through the shared move.
- Placement keeps the slowest sufficient CPU among allowed peers that can meet the deadline with near minimum tiebreak on minima, so light work never takes a fast CPU that other work needs.
- Flood and affinity stress skip forward with mask wins, so keep pinned work narrow and test with mixed masks before trusting tail latency.
- Overload past saturation runs best effort at `100%` utilization with miss cascade expected, so late work still drains in fair order with no admission drop while misses track the overload.
- Preempt sends at most one kick per wait when the arrival is eligible and leads by `100us` with more than `100us` still left on the owner, so urgent gaps preempt with no storm while near ties pace.
