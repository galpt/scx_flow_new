# scx_flow

## What

scx_flow is a knob-free deadline scheduler built on sched_ext. Each CPU owns an arena binary search tree ordered by virtual deadline (bounded at depth 32 with right-chained ties in insertion order) plus one fallback FIFO DSQ. Running tasks pay for burnt time scaled by effective weight. Virtual deadlines use a lag-conserving EEVDF model with shift-only EWMA burst prediction, sleep-to-sleep frame cadence detection, and producer-consumer wakeup inheritance. Placement uses burst-aware SMT and cache-tier scoring (L1 > L2 > L3, breaking ties by larger cache size buckets) with direct local dispatch on empty idle queues, deadline-aware in-place slice continuation for running tasks, and guarded preemption. Active cores run at maximum frequency and drop to half frequency only when no runnable tasks remain.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
