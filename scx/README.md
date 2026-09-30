# scx_flow

scx_flow is a Linux deadline daemon in Rust with a thin BPF core and 2ms slice.

### Queues

Core parks FIFO at overflow. Init reserves 522 queues with local plus node plus machine plus overflow. Dispatch drains overflow solely with FIFO. Daemon order stays a shadow view for observability. Tier counters for local plus node plus machine stay zero. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Keys

Deadlines quantize to 16 bit keys at 1024 nanos per step. Each key holds one FIFO queue. Tree finds least key in doubly logarithmic time. Order follows deadlines solely with stored shares for admission. Oracle tests cover order plus FIFO. See `src/rust/flow/veb.rs` and `src/bpf/intf.h`.

### Admission

Share equals 2ms times 1000 over period with 125 per mille at 16ms. Admitted plus share stays within 950 per mille. Stored shares add once and drop once through enqueue plus complete plus disable plus exit. Hints stay derived from weight keyed by task. Times stay monotonic. See `src/rust/flow/runtime.rs`.

### Gates

Gate runs first in every op. Stale CPUs plus tasks fail closed with one counter. Exiting work stays exempt. Ring reserve faults plus dashboard drops count one park. Wire gaps resync with one park. Reserved plus unknown kinds hold at the core. See `src/bpf/main/cpu.bpf.c` and `src/rust/flow/runtime.rs`.

### Reporting

Reporting uses `--stats` plus `--monitor` plus `--no-webui`. Dashboard serves loopback port `50005` with counters plus per CPU pid plus slice plus SMT plus version plus snapshot download. Parks sum core drops plus daemon parks. Misses use monotonic time. See `src/rust/stats.rs`.

## Code map

- Rules live in `src/bpf/intf.h`.
- Maps live in `src/bpf/main.bpf.c` with splits in `main/`.
- Order lives in `flow/veb.rs` with facade in `flow/mod.rs` and checks in `config.rs`.
- Dashboard lives in `snapshot.rs`, `topology.rs`, `stats.rs`, `webui.rs`, `ui/index.html`.

## Limitations

- Hotplug needs a restart.
- Releases need a restart.
- State is `16B` plus `8B` plus `8B` plus `120B`.
- Needs kernels, `7.2` series and up.
