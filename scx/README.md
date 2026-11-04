# scx_flow

## What

scx_flow places tasks by virtual time. Each LLC maps to one strand of a pair queue. The pair queue is a DHQ that runs in strict priority mode and picks the lowest virtual time first with ties going to strand A. When a pair is full or imbalanced the task goes to the per LLC queue. Dispatch checks the local pair first, then pairs on the same node, then pairs on other nodes, then LLC queues. A wakeup preempts the running task when its virtual time is smaller by at least 500000 nanos and the running slice has more than 125000 nanos left, else it wakes an idle CPU. Slice is 1000000 nanos. A requeued task keeps its remaining slice with virtual time advanced through the per pair sequence.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open and other apps in the background.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
- Needs kernel `7.2` or newer.
