# scx_flow

### What is it?

scx_flow runs the earliest deadline task first. It keeps deadline order in kernel priority queues with a burst predictor from recent runs. The core joins every task with no bound and a fixed `1ms` slice. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Why?

The goal is to test deadline order with prediction in the kernel and see if short bursts reach a CPU sooner. Finding the earliest deadline without a full scan matters when order decides who runs next. Direct queue order keeps the test fair. See `src/bpf/intf.h` and `src/bpf/enqueue.bpf.c`.

### How it works?

Arrivals pass a gate. Tasks earn deadlines from the predictor else the hint period with no admission bound. Each CPU takes the earliest deadline it may run. Teardown drops load at once with predictor update. See `src/bpf/enqueue.bpf.c`, `src/bpf/dispatch.bpf.c` and `src/rust/flow/edf.rs`.

## Typical Use Cases

- Latency sensitive apps. Tasks with the earliest deadline run first, so short arrivals never wait behind long work and stay responsive under load.
- Desktop use. A `1ms` slice keeps interaction smooth while background work continues, so typing stays fluid with no extra tuning.
- Mixed batch work. Deadline order keeps overload feasible, so heavy jobs still finish while urgent tasks move ahead in turn.

## More details

### Queues

One local queue per CPU plus one per node plus machine plus overflow hold tasks. Each pass drains local plus node plus machine in deadline order plus overflow in queue order with moves uncapped to remaining dispatch slots and visits capped at `64` per pass with resume next pass. No consumable slots leaves at once with no scan. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Each deadline orders as priority value with no runtime tiebreak. The predictor average plus deviation shapes later deadlines with shift updates plus a first deviation floor at average quarter. EDF order runs through the kernel priority queue with the deadline as vtime and no lag compensation. See `src/bpf/intf.h` and `src/rust/flow/edf.rs`.

### Admission

Tasks carry no share and every join counts one admit with no reject. The hint period shapes the first deadline while the predictor shapes later deadlines only. Rejects stay zero for wire compat with no run. Misses count past due on blocking ends. Past saturation at `100%` utilization the core still drains best effort in deadline order with miss cascade expected, so overload stays feasible with no admission drop. See `src/bpf/enqueue.bpf.c` and `src/rust/flow/edf.rs`.

### Gates

A gate runs first at each step so stale tasks and CPUs wait safely. Exiting work runs at once. Fails drop the ledger with no leak. The drain stays affinity gated with mask wins. One counter tracks held work. See `src/bpf/main/cpu.bpf.c`.

### Reporting

Flags `--stats`, `--monitor` and `--no-webui` show live counters as text or on a local page at `50005`. The page keeps local, node, machine, overflow, kicks apart. Snapshots share one moment for review. See `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Changes live in `CHANGELOG.md` with the `4.7.3` shape.
- Live kernel logic lives in `src/bpf/main.bpf.c` with parts in `src/bpf/main/`, `src/bpf/dispatch.bpf.c`, `src/bpf/dispatch/`, `src/bpf/enqueue.bpf.c`, `src/bpf/enqueue/`, `src/bpf/lifecycle.bpf.c`, `src/bpf/select_cpu.bpf.c` and `src/bpf/helpers/`. No `fair.c` helper is used and the queue order stays in kernel priority queues.
- Order lives in kernel priority queues with mirrors in `src/rust/flow/edf.rs`, `src/rust/flow/slot.rs`, `src/rust/flow/select.rs`, `src/rust/flow/preempt.rs`, `src/rust/flow/slice.rs` and `src/rust/flow/cgrp.rs` for tests only. The mirrors check deadline order plus saturation against the kernel logic, since no kernel test harness runs here.
- Deadline checks live in `src/bpf/main/deadline.bpf.c` with a mirror in `src/rust/flow/edf.rs` for tests only. The mirror keeps the same hint plus predictor math with no effect on order.
- Task burst bookkeeping lives in `src/rust/flow/edf.rs` with the slice in `src/rust/flow/slice.rs` plus checks in `src/rust/config.rs`.
- Speed levels live in `src/bpf/dispatch/perf.bpf.c` and run once per dispatch pass.
- Dashboard lives in `src/rust/snapshot.rs`, `src/rust/topology.rs`, `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`. Snapshots merge core admits, rejects, misses as source of truth.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `64B`, `8B`, `8B`, `120B`.
- Needs kernels, `7.2` series and up.
- Priority and FIFO never mix on one queue, since the kernel keeps one order per queue and a mix fails closed with an error.
- Mask wins on drain, since affinity gates every move with priority tiers plus overflow skipping to the next match through the shared move.
- Overflow stays FIFO with fail open drain, so stale deadlines never block live work and every pass still moves queued tasks in queue order with moves uncapped to remaining slots and visits capped at `64` per pass.
- Placement keeps the slowest sufficient CPU among allowed peers that can meet the deadline, so light work never takes a fast CPU that other work needs.
- Flood and affinity stress skip forward with mask wins, so keep pinned work narrow and test with mixed masks before trusting tail latency.
- Overload past saturation runs best effort at `100%` utilization with miss cascade expected, so late work still drains in deadline order with no admission drop while misses track the overload.
- Preempt sends at most one kick per park when the arrival leads by `100us` with more than `100us` still left on the owner, so urgent gaps preempt with no storm while near ties pace.
