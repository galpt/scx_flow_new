# scx_flow

## What

scx_flow places tasks by virtual time. Each LLC keeps four queues
ordered by virtual time with equal times in insertion order, plus
one fallback queue. Dispatch drains local first, then same node,
then remote. Wakeups preempt on gap else wake idle. Slice is fixed.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
