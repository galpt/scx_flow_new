# scx_flow

## What

scx_flow places tasks by virtual time. Each CPU keeps two queues
ordered by virtual time with equal times in insertion order, plus
one fallback queue. Running tasks pay for burnt time as they run.
Dispatch drains local first, then same LLC, then same node, then remote. Wakeups
wake idle only. Slice is fixed, and the fallback queue stays FIFO. Deadline sets the strand with gap preempts. Strands stay balanced with the larger side first.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Limitations

- Hotplug needs restart.
