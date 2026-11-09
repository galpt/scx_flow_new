# scx_flow

## What

scx_flow orders tasks by deadline. Each per-CPU queue holds tasks in
deadline order with equal deadlines in insertion order, plus one fallback
queue in FIFO order. Running tasks pay for burnt time. Virtual deadline adds
a burst scaled share step to the floored time. Dispatch drains local first,
then same LLC, then same node, then remote. Wakeups wake idle only with preempt on an earlier deadline. Slice is fixed at 1ms, and hotplug needs restart.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
