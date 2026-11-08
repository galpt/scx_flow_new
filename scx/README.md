# scx_flow

## What

scx_flow orders tasks by deadline.
Each per-CPU queue holds warm on strand A and cold on strand B in deadline order with insertion order for ties, draining earlier head first with ties to A, balanced cap 1.
Each queue holds without bound with fixed 1ms slices, plus one FIFO fallback as best-effort overflow.
Warm means last CPU shares same LLC. Placement picks least queued live queue. Dispatch drains local, most loaded, mates, same LLC, same node, then remote last with both strands in vd order. Virtual deadline (vd) adds share step to floored time.
Wakeups wake idle only with preempt on earlier deadline in same LLC with single kick. The tail stays informational.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
