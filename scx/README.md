# scx_flow

## What

scx_flow orders tasks by deadline. Each per-CPU queue holds
tasks in deadline order with equal deadlines in insertion order,
plus one fallback queue in FIFO order. Running tasks pay for burnt time.
Dispatch drains local first, then same LLC, then same node, then remote.
Wakeups wake idle only with preempt on an earlier deadline. Slice is fixed
at 1ms, and hotplug needs restart.
