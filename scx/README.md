# scx_flow

## What

scx_flow is a scheduler that focuses on providing a smooth modern-day desktop experience. Tasks enter a pair queue by virtual time and fall back to a per LLC queue when the pair is full or imbalanced, so interactive work keeps cache locality while bulk work still drains. Idle dispatch can take work from the local pair, then other pairs on the same node, then pairs on other nodes, then other LLC queues. A wakeup with a clearly smaller virtual time can preempt the running task, else it only wakes idle. The running task keeps its virtual time plus deadline plus slice on requeue.

## Typical Use Cases

- Latency-sensitive applications, such as audio editing.
- General desktop use, such as gaming with some browser tabs open and other apps running in the background.
- Mixed batch workloads, such as compiling, rendering, and others.

## Limitations

- Hotplug needs restart.
- Needs kernel `7.2` or newer.
