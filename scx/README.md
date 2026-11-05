# scx_flow

## What

scx_flow places tasks by virtual time. Each LLC has its own queue ordered by virtual time with equal times leaving in insertion order, plus one fallback queue. Dispatch drains the local LLC queue first, then same-node LLC queues, then remote ones. A wakeup preempts when its virtual time trails by at least the threshold else it wakes idle. Slice is fixed with no knobs. A requeued task keeps its remaining slice with virtual time advanced to stay monotonic.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open and other apps in the background.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
- Needs kernel with sched_ext enabled.
- Kernel 7.2 or newer is recommended.
