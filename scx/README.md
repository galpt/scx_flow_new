# scx_flow

## What

scx_flow is a scheduler that focuses on providing a smooth modern-day desktop experience. Tasks enter a pair queue by virtual time and fall back to a per LLC queue when the pair is full or imbalanced, so interactive work keeps cache locality while bulk work still drains.

## Typical Use Cases

- Latency-sensitive applications, such as audio editing.
- General desktop use, such as gaming with some browser tabs open and other apps running in the background.
- Mixed batch workloads, such as compiling, rendering, and others.

## Limitations

- Hotplug needs restart.
- Needs kernel `7.2` or newer.
