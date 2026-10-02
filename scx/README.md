# scx_flow

### What is it?

scx_flow runs the most urgent waiting task first. It keeps due time order in the kernel with a [Van Emde Boas tree](https://www.geeksforgeeks.org/dsa/van-emde-boas-tree-set-1-basics-and-construction/) from task weights. The core admits load under a bound with runs `2ms` fresh, up to `8ms` on repeat while empty, base under backlog. See `src/bpf/veb/` and `src/bpf/intf.h`.

### Why?

The goal is to test fast ordered queues in the kernel and see if urgent tasks reach a CPU sooner. Finding the earliest due time without a full scan matters when order decides who runs next. Bounded search keeps the test fair. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### How it works?

Arrivals pass a gate. Tasks get due times from weight and the core admits under a bound. All gated tasks carry keys with admits plus top key rejects in order. Each CPU takes the earliest. Teardown frees load at once. Rings stay review only. See `src/bpf/veb/`, `src/bpf/admit/`, `src/bpf/dispatch.bpf.c` and `src/rust/flow/runtime.rs`.

## Typical Use Cases

- Latency sensitive apps. Tasks with the earliest deadline run first, so short arrivals never wait behind long work and stay responsive under load.
- Desktop use. A `2ms` base slice keeps interaction smooth, growing to `8ms` for repeat work while empty and staying base under backlog, so typing stays fluid while background work continues.
- Mixed batch work. Admission keeps overload feasible, so heavy jobs still finish while urgent tasks move ahead in deadline order.

## More details

### Queues

One queue holds tasks. Each pass moves up to 16 in least key then deadline then owned then pid order. Fallback covers empty plus corrupt plus stale. Head skips tail walks. Fresh tasks take idle first when held while repeats reuse owner with headroom when allowed. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Each due time becomes a `16 bit` number at `1024 nanos` per step with top values held. Close times share one number in arrival order. A repeat keeps its place. The tree finds least without a scan and clears empty ones at once. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### Admission

Tasks carry shares from weight and the core holds load under `950 per mille` per CPU. Shares add once and drop once. Rejects park at the top key with no row or run. Misses count past due on blocking ends. Mirror keeps math for tests only. See `src/bpf/admit/` and `src/rust/flow/runtime.rs`.

### Gates

A gate runs first at each step so stale tasks and CPUs wait safely. Exiting work runs at once. Fails drop the ledger with no leak. The safety path stays affinity gated and rare. One counter tracks held work. Rings stay review only. See `src/bpf/main/cpu.bpf.c` and `src/rust/flow/runtime.rs`.

### Reporting

Flags `--stats`, `--monitor` and `--no-webui` show live counters as text or on a local page at `50005`. The page keeps ordered, safety runs, kicks apart. Snapshots share one moment for review. See `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Live kernel logic lives in `src/bpf/main.bpf.c` with parts in `src/bpf/main/`, `src/bpf/veb/`, `src/bpf/admit/`, `src/bpf/dispatch.bpf.c`, `src/bpf/dispatch/`, `src/bpf/enqueue.bpf.c`, `src/bpf/enqueue/`, `src/bpf/lifecycle.bpf.c`, `src/bpf/select_cpu.bpf.c` and `src/bpf/helpers/`.
- Order lives in `src/bpf/veb/` with a mirror in `src/rust/flow/veb.rs` for tests only. The mirror checks tree order plus saturation plus duplicates against the kernel logic, since no kernel test harness runs here.
- Admission lives in `src/bpf/admit/` with share, row, drop parts plus a mirror in `src/rust/flow/runtime.rs` for tests only. The mirror keeps the same share plus bound math with no effect on order. Rings carry notices for review only.
- Task load and order bookkeeping lives in `src/rust/flow/helpers.rs` and `src/rust/flow/mod.rs` with checks in `src/rust/config.rs`.
- Speed levels live in `src/bpf/dispatch/perf.bpf.c` and run once per dispatch pass.
- Dashboard lives in `src/rust/snapshot.rs`, `src/rust/topology.rs`, `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`. Snapshots merge core admits, rejects, misses as source of truth.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `40B`, `8B`, `8B`, `112B`.
- Needs kernels, `7.2` series and up.
- Spreading wakeups across eight nearby CPUs stays out by design, since early tests showed no gain and more scans cost time.
- Picking among local plus node plus machine queues with drain checks stays out by design, since the simple first live pick proved enough and extra checks cost time.
- Draining four fixed priority tiers in order stays out by design, since tier order beats due time order and extra moves cost time.
- Priority tiers lose to due time order, since tier order needs extra scans and moves while due time order runs the most urgent task first.
- Node and machine queues stay reserved with no tasks, so queue numbers stay stable across releases.
- Placement uses idle when live for fresh when held and repeats when empty, else last owner for repeats when held plus allowed plus idle, else the least loaded among the first sixteen CPU ids with idle exit, else first live, so fresh spread while repeats keep warmth without stacking.
- One shared waiting line stays in use with no change, since a single line keeps cache use simple and every CPU takes from it in due time order.
- Oversubscription past about seven admitted tasks per CPU at default weight parks the rest as rejects, so a 496 thread flood on 16 CPUs runs admitted in order while rejects drain ordered at the top key with higher latency.
- Flood throughput stays bounded by the `2ms` base slice plus queue wait under backlog with grown slices kept for empty tails only, so a deep flood still shows higher wakeup delay than light load even with ordered plus preempt work.
- Held tails park base, so a grown task parks base under backlog with one capped rule for admits plus rejects.
- Preempt sends at most one kick per park to the owner when the wakeup holds a row and leads by a margin with slice still long, with a running reject as longer while far rejects never preempt a reject run, so urgent gaps preempt longer runs with no storm.
