# scx_flow

## What

scx_flow is a knob-free latency score scheduler on sched_ext. Each LLC owns one kernel virtual deadline DSQ for shared tasks and each CPU owns one DSQ for pinned tasks plus one fallback FIFO DSQ. Wakeups inherit scores between wakers and workers with log scale runtime compression. Placement claims idle cores atomically across tiers (L1 > L2 > L3, ties keep fixed order) with direct local dispatch on won idle CPUs and in place slice continuation. Slices stay bounded and track a ten millisecond window with boost for long frame runs, and urgent tasks yield peers with a near stop claim and no interrupt. Active cores run at maximum frequency and idle cores decay to half on a timer.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
