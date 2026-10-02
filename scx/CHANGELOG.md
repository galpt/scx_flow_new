# Changelog

## 4.7.1

- Dispatch batch at `32` with the `nr_slots` clamp at entry and the remaining budget as the per tier bound. Flood at `8` past `128` queued with the step cap at `32`.
- Priority tiers skip within four probes through the shared move with mask wins on drain. Overflow keeps the `32` step cap in the same style.
- Preempt margin plus tail at `100us` with the floor at `100us` and one kick per park. The three kick points stay with no extra sender.
- First deviation floor at the max of error and average quarter with shifts plus clamp kept. Later samples keep quarter steps toward error.
- Docs plus validation track the new bounds. No `dhq.h` header is used and the queue order stays in kernel priority queues.
