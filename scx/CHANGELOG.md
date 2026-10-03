# Changelog

## 4.7.2

- Fixed slice at `1ms` with sixteen slices per `16ms` period. Task state at `64B` with no virtual runtime and no nice table.
- Dispatch carries no batch plus no flood plus no step cap plus no tier probes. Tiers plus overflow skip uniformly through the shared move with mask wins on drain.
- Joins carry no admission bound and no stored share. Every join counts one admit with no reject while the deadline predictor stays.
- Queue key is the virtual deadline vd equal to the absolute deadline, so the earliest vd wins with no lag compensation.
- Docs plus validation track the new shape. No `fair.c` helper is used and the queue order stays in kernel priority queues.

## 4.7.1

- Dispatch batch at `32` with the `nr_slots` clamp at entry and the remaining budget as the per tier bound. Flood at `8` past `128` queued with the step cap at `32`.
- Priority tiers skip within four probes through the shared move with mask wins on drain. Overflow keeps the `32` step cap in the same style.
- Preempt margin plus tail at `100us` with the floor at `100us` and one kick per park. The three kick points stay with no extra sender.
- First deviation floor at the max of error and average quarter with shifts plus clamp kept. Later samples keep quarter steps toward error.
- Docs plus validation track the new bounds. No `dhq.h` header is used and the queue order stays in kernel priority queues.
