# scx_flow

### What is it?

scx_flow is a CPU scheduler that runs the most urgent waiting task first. It uses a Van Emde Boas tree in the kernel to keep due time order from task weights. A helper keeps total load feasible and each run lasts a fixed slice of `2ms`. See `src/bpf/veb/` and `src/bpf/intf.h`.

### Why?

The goal is to try fast ordered queues in the kernel and learn if urgent tasks reach a CPU sooner. Finding the earliest due time without scanning the whole line matters when due order decides who runs next. The test keeps search cost bounded so the ordering gain can be judged fairly. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### How it works?

Arrivals pass a gate first so stale tasks wait safely. Each task gets a due time from its weight and joins a waiting line in due time order. A helper checks total load and lets tasks run while the line stays feasible, and tasks that do not fit wait without running. Each CPU takes waiting tasks starting with the earliest due time. When a task stops or exits it leaves the line and frees its load, and a safety path still runs waiting tasks when the ordered line stalls. See `src/bpf/veb/`, `src/bpf/dispatch.bpf.c` and `src/rust/flow/runtime.rs`.

## Typical Use Cases

- Latency sensitive apps. Tasks with the earliest deadline run first, so short arrivals never wait behind long work and stay responsive under load.
- Desktop use. A fixed `2ms` slice keeps interaction smooth, so typing and motion stay fluid while background work continues.
- Mixed batch work. Admission keeps overload feasible, so heavy jobs still finish while urgent tasks move ahead in deadline order.

## More details

### Queues

The waiting line lives in one shared queue and order comes from the ordered queue. Dispatch takes waiting tasks in due time order with live checks, so idle CPUs stay cheap. A safety path runs one waiting task when the ordered path stalls, so runnable tasks never wait on the helper. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Each due time becomes a short number of `16 bit` at `1024 nanos` per step with top values held at the top. Close due times can share one number and line up in arrival order within one number. The queue finds the smallest number and the next one without scanning the whole line, and empty numbers leave at once. Order follows due times only. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### Admission

Each task carries a small load share from its weight and the helper keeps total load under a bound of `950 per mille`. Shares add once and drop once when tasks finish or exit, so load never leaks. Shares that miss their finish notice return after a short grace of `128ms`. See `src/rust/flow/runtime.rs`.

### Gates

A gate checks every step first so stale tasks and CPUs wait safely instead of running in the wrong place. Exiting work runs through at once. One counter tracks held work so problems stay visible. See `src/bpf/main/cpu.bpf.c` and `src/rust/flow/runtime.rs`.

### Reporting

Flags of `--stats`, `--monitor` and `--no-webui` show live counters in text or in a local page on `50005` for review. The page shows ordered runs and safety runs apart with a short summary, so the ordering gain stays easy to read. Snapshots help share one moment for review. See `src/rust/stats.rs`, `src/rust/webui.rs` and `ui/index.html`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Live kernel logic lives in `src/bpf/main.bpf.c` with parts in `main/`, `veb/`, `dispatch/` and `helpers/`.
- Order lives in `src/bpf/veb/` with a mirror in `flow/veb.rs` for tests only.
- Task load and order bookkeeping lives in `flow/helpers.rs` and `flow/mod.rs` with checks in `config.rs`.
- Speed levels live in `src/bpf/dispatch/perf.bpf.c` and run once per dispatch pass.
- Dashboard lives in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs` and `ui/index.html`.
- Sections stay under fifty lines each with line counts not word counts.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `16B`, `8B`, `8B`, `112B`.
- Needs kernels, `7.2` series and up.
- Cursor spread eight peer scan stays dropped by design as homegrown.
- Gated local, node and machine router with `cpu_meets` stays dropped by design as homegrown.
- Fixed order four tier drain stays dropped by design as homegrown.
- Tiers lose since tier priority beats deadline priority with extra scans and moves.
- Node and machine queues stay reserved as ABI only with no tasks.
- Single tail, sticky previous and mask wins stays adopted with no change.
