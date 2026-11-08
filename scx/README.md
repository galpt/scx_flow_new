# scx_flow

## What

scx_flow orders tasks by deadline. Each per-CPU queue holds warm tasks on one strand and cold tasks on the other
in deadline order with equal deadlines in insertion order, draining the earlier head first, plus one fallback queue in FIFO order as best-effort overflow.
Each queue holds at most 10 tasks for at most 10ms with fixed 1ms slices (1ms ideal stays aspirational).
Dispatch drains local first, then mates, then same LLC, then same node, then remote. Wakeups wake idle only with preempt on an earlier deadline.
Hotplug needs restart. The 10ms tail target stays informational with no queue claim.
The tiny hint model stays offline with no queue write and no faster claim.
