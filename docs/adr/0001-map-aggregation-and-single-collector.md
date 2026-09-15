---
status: accepted
---

# Aggregate flows in eBPF maps behind one Collector

Z-Scope will aggregate packet and byte counters in bounded per-CPU eBPF maps attached at TC ingress/egress, then expose collection through one user-space `Collector` module. Per-packet delivery to user space is rejected because its wakeups, copies, and backpressure make the 1% CPU budget unpredictable; only bounded, deduplicated domain-evidence events may use a ring buffer because DNS, TLS SNI, and HTTP Host cannot be reconstructed from counters.

## Considered Options

- TC map aggregation: selected because it observes both ingress and egress at the Device Boundary and keeps the packet path bounded.
- XDP-only collection: rejected because it does not naturally cover outbound traffic with the same direction semantics.
- Per-packet RingBuf/PerfEvent delivery: rejected because cost scales with packet rate and user-space scheduling.
- Several public collectors for flows, domains, and health: rejected because callers would need to coordinate attachment lifetime, polling order, snapshots, and Observation Gaps.

## Consequences

- The supported kernel floor is Linux 6.6 with BTF; ZimaOS ships 6.18, so BTF and the modern TC attachment path are treated as guaranteed.
- On Linux 6.6+ programs attach through the tcx interface: no `clsact` qdisc is added, links are process-scoped, and attach health is verified with `query_tcx`. Older kernels fall back to the legacy netlink classifier path, which still adds a `clsact` qdisc.
- Flow data is snapshot-based and may be approximate when maps evict entries.
- The external collection interface stays small: start a worker, consume its bounded Tokio channel, and shut it down.
- Kernel ABI structs are fixed-size, versioned, `#[repr(C)]`, and separate from user-facing domain structs.
- Domain events use a bounded ring buffer and are deduplicated in user space; payload bytes are never retained after parsing.
- Domain evidence crosses the boundary as bounded payload samples: the packet path only peeks at constant offsets and copies at most 512 bytes, while DNS, TLS SNI and HTTP Host are parsed in user space. This keeps the verifier's state budget small and lets parsing rules evolve without kernel constraints.
- Storage, enrichment, and UI work occur downstream and cannot block the packet path. Bounded channel backpressure may delay user-space polling, which can increase observable ring-buffer drops without affecting network traffic.
