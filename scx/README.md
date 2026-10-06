# scx_flow

### What is it?

scx_flow 4.8.7 runs the fairest task first by virtual time. It keeps fair order in kernel priority queues with vruntime plus a burst predictor from recent runs. The core joins every waiting task with no bound and a fixed `1ms` slice. See `src/bpf/intf.h` and `src/bpf/dispatch.bpf.c`.

### Why?

The goal is to test fair order with prediction in the kernel and see if short bursts reach a CPU sooner. Like fair.c, earliest fair time runs first, unlike rt.c, no fixed priority holds. Direct queue order keeps the test fair and repeatable. See `src/bpf/intf.h`.

### How it works?

Arrivals always pass a gate first. Tasks earn EDF deadlines from the predictor else the hint period plus virtual deadlines from vruntime plus slice over weight. Each CPU takes the earliest fair time it may run. Teardown charges plus advances vruntime with predictor update always. See `src/bpf/enqueue.bpf.c` and `src/bpf/dispatch.bpf.c`.

## Typical Use Cases

Latency apps run urgent fair time first, so short arrivals skip long work. Desktop keeps `1ms` slices smooth with no tuning. Batch work drains best effort with misses tracked.

## More details

### Queues

One local queue per CPU plus one per node plus machine plus overflow hold tasks across 1042 queues. Each pass drains tiers plus steal with one hint move capped by slots and 8 visits. Five hints feed tiers plus steal plus perf with 4 to 8 steal peers. See `src/bpf/intf.h`.
Homeless plus gate misses wait in overflow FIFO with mask wins on drain.

### Keys

Each fair time orders as priority value with vruntime pacing via lag bounds. Predictor average plus deviation shapes deadlines with shift updates plus quarter floor. Virtual deadline adds slice over weight with one divide plus nice table. Fair key holds deadline plus virtual deadline with 2ms clamp. See `src/bpf/intf.h`.

### Admission

Tasks carry base weight 128, zero mapped to one, each join admits once with no reject. Effective stacks times hint over 128 with clamp while bands shape deadline and predictor shapes deadlines only. Rejects stay zero for wire compat in gate_rejects. Misses count on blocking ends. See `src/bpf/enqueue.bpf.c` and `src/rust/config.rs`.

### Gates

A gate runs first at each step so tasks and CPUs wait safely. Exiting work runs at once. Fails join overflow FIFO with no leak. Drain stays affinity gated with mask wins. Eligibility gates every kick, so hogs pace while lagging tasks wake. One counter tracks held work. See `src/bpf/cgroup.bpf.c`.

### Reporting

Flags `--stats`, `--monitor`, and `--no-webui` show counters as text or page at `50005`. Page keeps local, node, machine, overflow, kicks plus preempt with no loss. Snapshots share one moment with times. Dashboard shows fifteen counters plus uptime with CPU cards. Log shows cpus seeded primary plus llcs. See `src/rust/stats.rs`.

### Fairness

Fair order holds the earlier of deadline plus virtual deadline in each queue. Vruntime advances by slice over weight with lag clamped at 2ms. Sleepers gain at most one slice of boost with no storm. Hierarchy stays flat with no share accounting past weight. See `src/bpf/intf.h`.

### Weights

Weight tunes period bands plus fair share. Shares map to 32ms, 16ms, 8ms, and 4ms periods with shares 32, 64, 256, and 1024. Effective share stacks task times hint over 128. Heavy tasks earn near keys, light tasks earn far keys. See `src/bpf/cgroup.bpf.c`.

### Locality

Locality stays with per-CPU plus per-node queues. Select takes prev idle, then waker and sibling idle, before the pick, so pairs share cache without scan. Placement keeps the slowest sufficient CPU with near minimum tiebreak. Kicks clear idle with test and clear. Two-way SMT assumed. Span equals online. See `src/bpf/select_cpu.bpf.c`.

### Contention

Contention stays bounded with visits for tier moves. Base is 8 per pass shared across five tiers plus steal. Each tier moves at most one task bounded by slots before the next pick. Leftover work resumes next pass with no loss. Stats use per-CPU rows. See `src/bpf/dispatch.bpf.c`.

### Inversion

Mask wins bound inversion with fail open. Each move checks the CPU mask and picks earliest fair time first, so foreign heads skip to the next task and tier, with blocked tiers local only. Overflow drains last in arrival order. Homeless work waits there with no stall. See `src/bpf/dispatch.bpf.c`.

### Staleness

Staleness heals with predictor retrain plus minimum fold forward. Each stop feeds average plus deviation with shift updates. Idle minima hold bounded by lag plus eligibility, so rejoins keep one slice boost. Hints race moves benignly to the next pass. See `src/bpf/lifecycle.bpf.c`.

### Verification

Fmt, clippy, build, and test stay clean. Veristat holds 20 programs below one million steps. Guard holds version plus mirrors gone with no property return. See `src/bpf/main.bpf.c`.

## Code map

Rules live in `src/bpf/intf.h`. Core lives in cgroup, weight, vtime, edf, placement, select, enqueue, preempt, dispatch, lifecycle, stats, and timer, with select plus enqueue split. Init lives in main plus topology. Dashboard lives in snapshot, stats, topology, webui, and ui.

## Limitations

Hotplug and releases need a restart. State is `64B`, `16B`, `8B`, `120B`. Needs kernel `7.2` or later. Mask wins on drain. One kick per wait with `100us` margin and tail. Governor performance with half and max. Equal ties keep lower id with no extra kick. Extra threads stay single.
