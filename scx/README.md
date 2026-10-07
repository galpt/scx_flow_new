# scx_flow

### What is it?

scx_flow 4.8.11 runs the earliest strict key first as the earlier of deadline plus virtual time. It adds RED admission with guarantee-only tolerance plus three PRIQ tiers with insert vtime plus a value ordered reject queue outside dispatch plus reclaim on saved delta. See `src/bpf/intf.h` and `src/bpf/edf.bpf.c`.

### Why?

The goal is to test strict order with prediction in the kernel and see if short bursts reach a CPU sooner. Like fair.c, earliest strict key runs first, unlike rt.c, no fixed priority holds. Direct queue order keeps the test fair and repeatable with no tuning. See `src/bpf/intf.h`.

### How it works?

Arrivals pass a gate first, then pass RED with residual plus tolerance used only for the guarantee. A zero exceed admits, a critical exceed admits with no swap, else the newcomer rejects to the value ordered queue. Each CPU takes the earliest key it may run. See `src/bpf/enqueue.bpf.c` and `src/bpf/dispatch.bpf.c`.

## Typical Use Cases

Latency apps run urgent fair time first, so short arrivals skip long work with no wait. Desktop keeps `1ms` slices smooth with no tuning across CPUs. Batch work drains best effort with misses tracked plus RED rejects counted. Servers hold overload with value order plus reclaim on saved time.

## More details

### Queues

One local queue per CPU plus one per node plus machine plus reject hold tasks across 1042 queues. Each pass drains three PRIQ tiers plus steal with one move capped by slots and 8 visits plus one reclaim when empty. Reject stays value ordered outside dispatch. See `src/bpf/intf.h`.

### Keys

Each strict key sets queue rank with vruntime pacing via lag bounds. Predictor shapes deadlines with shift updates. Virtual deadline adds dynamic slice over weight with one divide. Strict key holds earlier of deadline plus virtual deadline with 2ms clamp. Remaining feeds slice plus slack only. See `src/bpf/intf.h`.

### Admission

RED checks residual from deadline minus cost plus tolerance of zero for critical else `64us`. Load scales by 1024 with exceed when late. Victim needs least value plus cost past exceed plus deadline before newcomer plus never critical, else the newcomer rejects to the value ordered queue. See `src/bpf/edf.bpf.c` and `src/rust/config.rs`.

### Gates

A gate runs first so tasks and CPUs wait. Exiting work runs at once with no wait and no gate. Fails join the value ordered reject queue with no leak. Drain stays gated with mask wins. Eligibility gates every kick, so hogs pace while lagging tasks wake. See `src/bpf/cgroup.bpf.c`.

### Reporting

Flags `--stats`, `--monitor`, and `--no-webui` show counters as text or page at `50005`. Page keeps local, node, machine, kicks, preempt, plus RED rejects plus reclaims. Snapshots share one moment with times plus topology. Dashboard shows seventeen counters plus uptime with CPU cards plus five key merged JSON intact. See `src/rust/stats.rs`.

### Fairness

Strict order holds the earlier of deadline plus virtual deadline in each queue. Vruntime advances by slice over weight with lag clamp. Sleepers gain at most one slice of boost with no storm. Adaptive steps change the slice with no virtual change. Hierarchy stays flat with no share past weight. See `src/bpf/intf.h`.

### Weights

Weight tunes period bands. Shares map to 32ms, 16ms, 8ms, and 4ms periods with shares 32, 64, 256, and 1024. Effective share stacks task times hint over 128 with zero mapped to 128. Heavy tasks earn near keys, light tasks earn far keys. Value holds weight with top critical. See `src/bpf/cgroup.bpf.c`.

### Locality

Locality stays with per-CPU plus per-node queues. Select takes prev idle, then waker and sibling idle, before the pick, so pairs share cache. Placement keeps the slowest sufficient CPU with prev tie plus near minimum. Two-way SMT assumed. Span equals online CPUs with no hotplug use. See `src/bpf/select_cpu.bpf.c`.

### Contention

Contention stays bounded with 8 visits per pass shared across three PRIQ tiers plus steal. Each tier moves one task by slots. Steal scans 4 to 8 peers node-local first with idle hold at 4 on gate plus miss pressure. Reclaim moves one reject when tiers hold no work. See `src/bpf/dispatch.bpf.c`.

### Inversion

Mask wins bound inversion with fail open. Each move checks the CPU mask and picks time first, so heads skip to the next task and tier. Reject stays outside dispatch with reclaim on same key or after. Local on stays terminal at three sites with no global use. See `src/bpf/dispatch.bpf.c`.

### Staleness

Staleness heals with retrain plus minimum fold. Each stop feeds average plus deviation plus saved delta from cost. Yields keep slice up to `1ms` when critical, else adapt by `64us` up on a miss else `128us` down to `10us` plus `1ms`. Reclaim needs saved past `128us` with positive laxity. See `src/bpf/lifecycle.bpf.c`.

### Verification

Fmt, clippy, build, and test stay clean. Veristat holds 20 programs below one million steps. Guard holds version plus mirrors gone with no property return. Code stays self-contained with no knobs plus no docs plus no changelog. Needs kernel `7.2` or later with one kick per wait. See `src/bpf/main.bpf.c`.

## Code map

Rules live in `src/bpf/intf.h` with RED plus adapt helpers. Core lives in cgroup, weight, vtime, edf, placement, select, enqueue, preempt, dispatch, lifecycle, stats, and timer, with select plus enqueue split. Init lives in main plus topology. Dashboard lives in snapshot, stats, topology, webui, and ui.

## Limitations

Hotplug and releases need restart. State is `72B`, `16B`, `8B`, `136B`. Needs kernel `7.2` or later. Mask wins on drain. One kick per wait with predictor slack plus `100us` margin and tail. Governor performance with half and max. Tied minima prefer prev CPU, then lower id. Extra threads stay single.
