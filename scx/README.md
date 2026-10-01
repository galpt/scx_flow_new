# scx_flow

### What is it?

scx_flow is a sched-ext scheduler that replaces FIFO plus rbtree queue ordering for CPU dispatch with a [Van Emde Boas tree](https://www.geeksforgeeks.org/dsa/van-emde-boas-tree-set-1-basics-and-construction/). The tree is the queues in BPF with summary, clusters, counts, pid rows, root. Duplicates share one key with park order deciding within one key. The daemon admits under the bound. The slice stays fixed at 2ms. See `src/bpf/veb/` and `src/bpf/intf.h`.

### Why?

The goal is to test what happens when a CPU scheduler uses a Van Emde Boas tree in BPF. A Van Emde Boas tree may beat FIFO, priority queue, BST, rbtree for least deadline search. BPF keeps the tree accurate with bounded loops and fail closed parks. The tree finds least in constant time plus successor in doubly logarithmic steps and may beat FIFO scan plus rbtree O(log n) at dispatch, and that ordering win may outweigh the tree costs with verifier footprint, fixed maps, bounded probes when deadlines drive dispatch order. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### How it works?

Task arrival hits the gate first with stale CPUs plus tasks failing closed. The core derives one deadline from weight derived period plus now then quantizes to one 16 bit key at 1024 nanos per step with saturate at top. Enqueue inserts the key in the tree, parks at the overflow tail, notifies the daemon with one sequence, and the daemon admits under 950 per mille with rejects parking and no run. Dispatch starts from the least key and follows successors in tree order up to 16 moves capped at 20 probes with sequence, liveness, affinity checks, and empty tree or stall moves one affinity gated head task to the dispatch CPU with keyed drop so runnable tasks never wait. Stopping, disable, exit drop the tree key plus notify complete, and the daemon drops the stored share once with lost shares collected past deadline plus 128ms grace. Duplicates share one key with park order deciding within one key, and the tree finds least plus successor in doubly logarithmic time with cached least in constant time, so ordered search may beat FIFO scan plus rbtree O(log n) when deadlines drive dispatch order. See `src/bpf/veb/`, `src/bpf/dispatch.bpf.c`, `src/rust/flow/runtime.rs`.

## Typical Use Cases

- Deadline ordered runs. BPF vEB queues keep least key order with bounded probes, so deadline driven work gains ordered moves with fail open cover when the tree stalls.
- Admission bound checks. Rust daemon ledger pairs share, order, task single exit under 950 per mille, so overload parks early with no runaway queue growth.
- Hierarchy neutral hosts. Thin stub passes init, move, weight with no policy in BPF, so transitions stay balanced while hints stay derived from weight.
- Benefit review on dashboard. Loopback dashboard shows vEB hits, FIFO parks, `TL;DR`, `Explanation` at ninety five share, so ordered gain needs no log scraping.

## More details

### Queues

Core parks at overflow with tree insert. Init reserves 522 queues as an ABI placeholder with local, node, machine, overflow. Dispatch moves admitted tasks in tree order up to 16 per pass with sequence, liveness, affinity checks and parks missing order plus stale sequence with no tree drop. Empty queue leaves at once with no scan. Empty tree or stall moves one affinity gated head task with liveness plus affinity checks plus keyed drop and no order gate so runnable tasks never wait on the daemon. Probes cap at 20 with empty skip through counts plus drained advance so one pass never scans the tail more than 20 times. Daemon order holds within 512 entries with rejects parking and no run. Userspace queue holds 1024 events with drain cap 1024 and drops count parks. Over moves count progress. Bounds stay predicted from probe counts with veristat measured in CI plus no live benchmarks. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Deadlines quantize to 16 bit keys at 1024 nanos per step. Universe holds 65536 keys with shift 10 covering 67ms with saturate at top. Duplicates share one key with park order deciding within one key. Tree finds least key in doubly logarithmic time with summary, clusters, min, max. Bit scans use trailing plus leading zeros with zero check. Counts bump before pid link so full maps never leave phantom keys with rollback plus one park. Zero counts clear bits at once so empty keys never linger. Root races across CPUs with least taking the smaller of cached plus scan. Order follows deadlines solely with stored shares for admission. Removal drops the pid key on stopping, disable, exit with keyed drop solely on move when the stored key still matches. Oracle tests cover order plus duplicates. See `src/bpf/veb/` and `src/rust/flow/veb.rs`.

### Admission

Share equals 2ms times 1000 over period with 125 per mille at 16ms. Admitted plus share stays within 950 per mille. Stored shares add once and drop once through enqueue, complete, disable, exit. Lost completes collect past deadline plus 128ms grace. Task rows cap at 4096 with zero identifiers parking at once. Hints stay derived from weight keyed by task. Times stay monotonic. See `src/rust/flow/runtime.rs`.

### Gates

Gate runs first in every op. Stale CPUs plus tasks fail closed with one counter and stale select returns error. Gate fail stopping notifies when queued so shares return at once. Exiting work stays exempt. Ring reserve faults plus dashboard drops count one park with single count. Wire gaps resync with one park and first sequence accepts mid attach. Reserved plus unknown kinds hold at the core. One sequence serves task state, wire, order entry. See `src/bpf/main/cpu.bpf.c` and `src/rust/flow/runtime.rs`.

### Reporting

Reporting uses `--stats`, `--monitor`, `--no-webui`. Dashboard serves loopback port `50005` with counters, per CPU pid, slice, SMT, version, snapshot download plus vEB hits plus FIFO parks cards plus `TL;DR` plus `Explanation`. Rings poll each 10ms decoupled from 100ms dashboard cache with one second page poll reusing `/api/stats` plus `/api/snapshot`. Parks sum core drops, daemon parks, queue drops. Ordered moves count vEB hits plus fail open moves count FIFO parks with completions apart. `TL;DR` says running tasks gain or miss ordered queues at ninety five share over the completions window with math plus fail-open share in `Explanation`. Misses use monotonic time and file names use wall time. Wire holds fourteen counters at `112B`. See `src/rust/stats.rs`, `src/rust/webui.rs`, `ui/index.html`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Maps live in `src/bpf/main.bpf.c` with splits in `main/` plus `veb/` plus `dispatch/` for the level helper plus `helpers/` for paired move plus finish.
- Order lives in `src/bpf/veb/` with oracle mirror plus BPF bitmap differential in `flow/veb.rs` plus facade in `flow/mod.rs` and checks in `config.rs`. Ledger pairing lives in `flow/helpers.rs` with share, order, task single exit.
- BPF holds live scheduling logic under verifier while Rust holds test only mirrors, oracle, config validation, daemon ledger, snapshot, webui. Mirrors never drive dispatch. Pair `cgroup.bpf.c` plus `flow/cgrp.rs` shows live stubs plus test only hints. See `flow/mod.rs` plus `bpf/veb/`.
- Level lives in `src/bpf/dispatch/perf.bpf.c` with paired boost plus idle from per CPU depth and no call on steady through one dispatch exit. See `src/bpf/dispatch.bpf.c` and `src/bpf/intf.h`.
- Dashboard lives in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs`, `ui/index.html` with vEB hits, FIFO parks, `TL;DR`, `Explanation`.
- Sections stay under fifty lines each with line counts not word counts.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `16B`, `8B`, `8B`, `112B`.
- Needs kernels, `7.2` series and up.
- Cursor spread eight peer scan stays dropped by design as homegrown.
- Gated local, node, machine router with `cpu_meets` stays dropped by design as homegrown.
- Fixed order four tier drain stays dropped by design as homegrown.
- Tiers lose since tier priority beats deadline priority with extra scans plus moves.
- Node plus machine queues stay reserved as ABI only with no tasks.
- Single tail, sticky previous, mask wins stays adopted with no change.
