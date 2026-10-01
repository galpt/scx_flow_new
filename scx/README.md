# scx_flow

### What is it?

scx_flow is a CPU scheduler that runs the most urgent waiting task first. It uses a [Van Emde Boas tree](https://www.geeksforgeeks.org/dsa/van-emde-boas-tree-set-1-basics-and-construction/) in the kernel to keep due time order from task weights. A helper keeps total load feasible and each run lasts a fixed slice of `2ms`. See `src/bpf/veb/` and `src/bpf/intf.h`.

### Why?

The goal is to try fast ordered queues in the kernel and learn if urgent tasks reach a CPU sooner. Finding the earliest due time without scanning the whole line matters when due order decides who runs next. The test keeps search cost bounded so the ordering gain can be judged fairly. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### How it works?

Arrivals pass a gate first so stale tasks wait safely. Each task gets a due time from its weight and the core checks its load share against the per CPU sum under the bound. Admitted tasks join the waiting line in due time order with a tree key plus an order row written at once, and tasks that do not fit wait without running. Each CPU takes admitted tasks starting with the earliest due time with no wait for outside help. When a task stops or exits it leaves the line and frees its load at once in the core, and a safety path still runs waiting tasks when the ordered line stalls but stays rare since rows land at once. Rings carry notices for review only with loss having no effect on order. The outside helper watches counters only. See `src/bpf/veb/`, `src/bpf/admit/`, `src/bpf/dispatch.bpf.c` and `src/rust/flow/runtime.rs`.

## Typical Use Cases

- Latency sensitive apps. Tasks with the earliest deadline run first, so short arrivals never wait behind long work and stay responsive under load.
- Desktop use. A fixed `2ms` slice keeps interaction smooth, so typing and motion stay fluid while background work continues.
- Mixed batch work. Admission keeps overload feasible, so heavy jobs still finish while urgent tasks move ahead in deadline order.

## More details

### Queues

The waiting line lives in one shared queue and order comes from the ordered queue kept in the core. Dispatch takes admitted tasks in due time order with live checks, so idle CPUs stay cheap. Each pass moves at most `16` tasks within at most `20` number checks, and a drained line exits the pass at once. A safety path runs one waiting task when the ordered path stalls, so runnable tasks never wait on outside help, but it stays rare since rows land at once and only true affinity gaps reach it. Rings carry notices for review only. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Each due time becomes a short number of `16 bit` at `1024 nanos` per step with top values held at the top. Close due times can share one number and line up in arrival order within one number. A task that arrives again with the same number stays where it waits with its old due time. The queue finds the smallest number and the next one without scanning the whole line, and empty numbers leave at once. Order follows due times only. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### Admission

Each task carries a small load share from its weight and the core keeps total load under a bound of `950 per mille` with per CPU sums. Shares add once at park time and drop once when tasks stop, disable, or exit, so load never leaks. Rejects park at once with no key, no row, and no run. Stale tasks clear at once, so no empty row lingers. Misses count when blocking ends pass the due time. A userspace mirror keeps the same math for tests and review only with no effect on order. Rings carry notices for review only. See `src/bpf/admit/` and `src/rust/flow/runtime.rs`.

### Gates

A gate checks every step first so stale tasks and CPUs wait safely instead of running in the wrong place. Exiting work runs through at once. Gate fails drop the ledger at once with no leak. The safety path stays affinity gated and rare since rows land at once. One counter tracks held work so problems stay visible. Rings carry notices for review only. See `src/bpf/main/cpu.bpf.c` and `src/rust/flow/runtime.rs`.

### Reporting

Flags of `--stats`, `--monitor` and `--no-webui` show live counters in text or in a local page on `50005` for review. The page shows ordered runs and safety runs apart with a short summary, so the ordering gain stays easy to read. The page also shows kicks that wake idle CPUs when parked work arrives. Snapshots help share one moment for review. See `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Live kernel logic lives in `src/bpf/main.bpf.c` with parts in `src/bpf/main/`, `src/bpf/veb/`, `src/bpf/admit/`, `src/bpf/dispatch/` and `src/bpf/helpers/`.
- Order lives in `src/bpf/veb/` with a mirror in `src/rust/flow/veb.rs` for tests only. The mirror checks tree order plus saturation plus duplicates against the kernel logic, since no kernel test harness runs here.
- Admission lives in `src/bpf/admit/` with share, row, drop parts plus a mirror in `src/rust/flow/runtime.rs` for tests only. The mirror keeps the same share plus bound math with no effect on order. Rings carry notices for review only.
- Task load and order bookkeeping lives in `src/rust/flow/helpers.rs` and `src/rust/flow/mod.rs` with checks in `src/rust/config.rs`.
- Speed levels live in `src/bpf/dispatch/perf.bpf.c` and run once per dispatch pass.
- Dashboard lives in `src/rust/snapshot.rs`, `src/rust/topology.rs`, `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`. Snapshots merge core admits, rejects, misses as source of truth.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `24B`, `8B`, `8B`, `112B`.
- Needs kernels, `7.2` series and up.
- Spreading wakeups across eight nearby CPUs stays out by design, since early tests showed no gain and more scans cost time.
- Picking among local plus node plus machine queues with drain checks stays out by design, since the simple first live pick proved enough and extra checks cost time.
- Draining four fixed priority tiers in order stays out by design, since tier order beats due time order and extra moves cost time.
- Priority tiers lose to due time order, since tier order needs extra scans and moves while due time order runs the most urgent task first.
- Node and machine queues stay reserved with no tasks, so queue numbers stay stable across releases.
- Placement uses the selected CPU when live, else an idle CPU when live, else the first live CPU, so warmth stays cheap with no extra scan.
- One shared waiting line stays in use with no change, since a single line keeps cache use simple and every CPU takes from it in due time order.
