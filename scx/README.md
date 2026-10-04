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

One local queue per CPU plus one per node plus machine plus overflow hold tasks across 1042 queues. Each pass drains tiers plus steal with one hint move capped by slots and 8 visits. Five hints feed tiers plus steal plus perf with 4 to 8 steal peers. See `src/bpf/intf.h`.
Homeless plus gate misses wait in overflow FIFO with mask wins on drain.

### Keys

Each fair time orders as priority value with vruntime pacing via lag bounds. Predictor average plus deviation shapes deadlines with shift updates plus quarter floor. Virtual deadline adds slice over weight with one divide plus nice table. Fair key holds deadline plus virtual deadline with 2ms clamp. See `src/bpf/intf.h`.

### Admission

Tasks carry base weight 128, zero mapped to one, each join admits once with no reject. Effective stacks times hint over 128 with clamp while bands shape deadline and predictor shapes deadlines only. Rejects stay zero for wire compat in gate_rejects. Misses count on blocking ends. See `src/bpf/enqueue.bpf.c` and `src/rust/flow/slice.rs`.

### Gates

A gate runs first at each step so tasks and CPUs wait safely. Exiting work runs at once. Fails join overflow FIFO with no leak. Drain stays affinity gated with mask wins. Eligibility gates every kick, so hogs pace while lagging tasks wake. One counter tracks held work. See `src/bpf/cgroup.bpf.c`.

### Reporting

Flags `--stats`, `--monitor` and `--no-webui` show counters as text or on a page at `50005`. Page keeps local, node, machine, overflow, kicks plus preempt apart with no loss. Snapshots share one moment for review with times now. Dashboard shows fifteen counters plus uptime with CPU cards. See `src/rust/stats.rs`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Changes live in `CHANGELOG.md` with the `4.8.2` shape.
- Live kernel logic lives in `src/bpf/main.bpf.c` with parts in `src/bpf/cgroup.bpf.c`, `src/bpf/weight.bpf.c`, `src/bpf/vtime.bpf.c`, `src/bpf/edf.bpf.c`, `src/bpf/task_placement.bpf.c`, `src/bpf/select_cpu.bpf.c` plus `src/bpf/select/idle.bpf.c` and `src/bpf/select/scan.bpf.c`, `src/bpf/enqueue.bpf.c` plus `src/bpf/enqueue/target.bpf.c`, `src/bpf/enqueue/insert.bpf.c` and `src/bpf/enqueue/kick.bpf.c`, `src/bpf/preempt.bpf.c`, `src/bpf/dispatch.bpf.c`, `src/bpf/lifecycle.bpf.c`, `src/bpf/stats.bpf.c` and `src/bpf/timer.bpf.c`. No `fair.c` helper is used and the queue order stays in kernel priority queues.
- Order lives in kernel priority queues with test-only math mirrors in `src/rust/flow/edf.rs`, `src/rust/flow/slot.rs`, `src/rust/flow/select.rs`, `src/rust/flow/preempt.rs`, `src/rust/flow/slice.rs`, `src/rust/flow/weight.rs`, `src/rust/flow/vtime.rs`, `src/rust/flow/dispatch.rs`, `src/rust/flow/lifecycle.rs`, `src/rust/flow/timer.rs`, `src/rust/flow/property.rs` and `src/rust/flow/cgrp.rs`. The mirrors check fair order plus vruntime plus saturation with no map use, since no kernel test setup runs here.
- Deadline plus fair checks live in `src/bpf/edf.bpf.c` with a mirror in `src/rust/flow/edf.rs` for tests only. The mirror keeps the same hint plus predictor plus vruntime math with no effect on order.
- Task vruntime bookkeeping lives in `src/rust/flow/vtime.rs` with the slice plus scaler plus effective share in `src/rust/flow/slice.rs` plus placement in `src/rust/flow/select.rs` plus kicks in `src/rust/flow/preempt.rs` plus checks in `src/rust/config.rs`.
- Speed levels live in `src/bpf/dispatch.bpf.c` and run once per dispatch pass.
- Dashboard lives in `src/rust/snapshot.rs`, `src/rust/topology.rs`, `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`. Snapshots merge core admits, rejects, misses, preempt kicks plus skipped as source of truth.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `64B`, `16B`, `8B`, `120B`.
- Needs kernels, `7.2` series and up.
- Priority queues never mix orders, since the kernel keeps one fair key per queue and a mix fails closed with an error.
- Mask wins on drain, since affinity gates every move with priority tiers skipping to the next match through the shared move.
- Placement keeps the slowest sufficient CPU in two node-local phases with near minimum tiebreak on minima, so light work never takes a fast CPU while close peers win first.
- The best sufficient fallback spreads symmetric hosts with drain plus minimum plus id tiebreak. SSF scans 8 peers from cursor plus one plus BSF scans the next 4 from cursor plus 9 with shared plus two advance. Needs 12 CPUs for 12 unique else overlap.
- The shared cursor serves select plus steal with stride two and best effort races, so passes spread with no hotspot.
- Idle CPUs hold a stale minimum bounded by 2ms lag plus eligibility, so rejoins keep one slice boost with no decay timer.
- Queue hints race moves with benign TOCTOU, so a stale hint only delays work to the next pass with no loss. Hint moves thread hoisted depths with no second poll.
- Toolchain stays on stable `1.91` with `clippy -Dwarnings`, so checks stay repeatable with no extra allow.
- Flood and affinity stress skip forward with mask wins, so keep pinned work narrow and test with mixed masks before trusting tail latency.
- Overload past saturation runs best effort at `100%` utilization with miss cascade expected, so late work still drains in fair order plus overflow FIFO with no admission drop while misses track the overload.
- Preempt sends at most one kick per wait when arrival is eligible and leads by `100us` with over `100us` left on owner, so urgent gaps preempt with no storm while ties pace. Kicks count in preempt_kicks, held kicks in preempt_skipped, and eligibility lag holds count as skipped.
- No latency or throughput targets are claimed. Completion plus probe delay are the only bench signals with no per-op latency histogram, so report topology plus variance with each run.
