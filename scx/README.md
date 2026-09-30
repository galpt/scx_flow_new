# scx_flow

### What is it?

scx_flow is a sched-ext scheduler that tries a Van Emde Boas tree for CPU order. The tree lives fully in Rust. BPF stays minimal with gate, park, notify, execute. The slice stays fixed at 2ms. See `src/rust/flow/veb.rs` and `src/bpf/intf.h`.

### Why?

The goal is to test what happens when a CPU scheduler uses a Van Emde Boas tree. A Van Emde Boas tree may beat priority queue, BST, rbtree for least deadline search. Rust keeps the tree accurate with tests for order plus FIFO. The benefits may outweigh the overhead when deadlines drive placement. See `src/rust/flow/veb.rs` and `src/rust/flow/runtime.rs`.

## More details

### Queues

Core parks at overflow with deadline vtime. Init reserves 522 queues as an ABI placeholder with local, node, machine, overflow. Dispatch moves admitted tasks in daemon order up to 16 per pass with sequence plus liveness checks and parks stale entries. Empty order or stall fails open with one head move so progress stays bounded. Daemon order drives dispatch within 512 entries with rejects parking and no run. Userspace queue holds 1024 events with drain cap 1024 and drops count parks. Over moves count progress. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Deadlines quantize to 16 bit keys at 1024 nanos per step. Each key holds one FIFO queue. Tree finds least key in doubly logarithmic time. Order follows deadlines solely with stored shares for admission. Removal scans one key queue within 512 entries. Oracle tests cover order plus FIFO. See `src/rust/flow/veb.rs` and `src/bpf/intf.h`.

### Admission

Share equals 2ms times 1000 over period with 125 per mille at 16ms. Admitted plus share stays within 950 per mille. Stored shares add once and drop once through enqueue, complete, disable, exit. Lost completes collect past deadline plus 128ms grace. Task rows cap at 4096. Hints stay derived from weight keyed by task. Times stay monotonic. See `src/rust/flow/runtime.rs`.

### Gates

Gate runs first in every op. Stale CPUs plus tasks fail closed with one counter and stale select returns error. Exiting work stays exempt. Ring reserve faults plus dashboard drops count one park with single count. Wire gaps resync with one park and first sequence accepts mid attach. Reserved plus unknown kinds hold at the core. One sequence serves task state, wire, order entry. See `src/bpf/main/cpu.bpf.c` and `src/rust/flow/runtime.rs`.

### Reporting

Reporting uses `--stats`, `--monitor`, `--no-webui`. Dashboard serves loopback port `50005` with counters, per CPU pid, slice, SMT, version, snapshot download. Rings poll each 10ms decoupled from 100ms dashboard cache. Parks sum core drops, daemon parks, queue drops. Misses use monotonic time and file names use wall time. See `src/rust/stats.rs`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Maps live in `src/bpf/main.bpf.c` with splits in `main/`.
- Order lives in `flow/veb.rs` with facade in `flow/mod.rs` and checks in `config.rs`.
- Dashboard lives in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs`, `ui/index.html`.
- Sections stay under fifty lines each with line counts not word counts.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `16B`, `8B`, `8B`, `96B`.
- Needs kernels, `7.2` series and up.
