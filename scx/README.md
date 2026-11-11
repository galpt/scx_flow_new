# scx_flow

## What

scx_flow orders tasks by deadline. Each per-CPU queue holds tasks in
deadline order with equal deadlines in insertion order, plus one fallback
queue in FIFO order. Running tasks pay for burnt time. Virtual deadline adds
a burst scaled effective step to the floored time. Steady tasks price by the kept
max run length with short tasks exact and long tasks in one slice quanta.
Unknown tasks keep the burst path. A full target keeps the newcomer in
fallback in FIFO order with no evict. Stopping plus tick keep the burst
and run state with idle only kick and no reclaim. Dispatch drains local first,
then same LLC, then same node, then remote. Wakeups wake idle only with preempt on an earlier deadline. Slice is fixed at 1ms, and hotplug needs restart.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
