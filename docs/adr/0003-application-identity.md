---
status: accepted
---

# Attribute Application Identity to Flows instead of counting socket traffic separately

Z-Scope will attribute processes and applications to existing boundary Flows by capturing socket ownership at connect/listen time with a cgroup `sock_ops` eBPF program and joining it to Flow snapshots in user space. Packet and byte counters stay owned by TC; the Application Identity is metadata on top of the boundary truth. A second socket-layer byte accounting system is rejected because its totals cannot be reconciled with the Device Boundary product language (retransmissions, L2 headers, forwarded traffic), and `/proc`-scanning attribution is rejected because it misses short-lived connections and costs a full descriptor sweep per interval.

## Considered Options

- Socket-layer byte counting (kprobe `sendmsg`/`recvmsg`): rejected because "Σ(process) = boundary total" would stop being true, and the product would need two irreconcilable byte definitions.
- `/proc` + `sock_diag` polling (nethogs-style): rejected as the attribution source because short-lived connections disappear between scans and the sweep is expensive; it may still be used for user-space enrichment (executable path, container metadata).
- Kernel-side join in the TC program (owner fields in `FlowValue`): rejected because it couples the packet path to attribution state and grows every Flow record; the owner map is read once per poll, so a user-space join carries the same information with no hot-path cost.
- cgroup-only attribution (`bpf_skb_cgroup_id` at TC): rejected because forwarded container traffic crosses a veth where `skb->sk` is cleared, and host processes share the root cgroup, so per-process identity would be lost.

## Consequences

- The owner key omits the local address and uses `(protocol, local port, remote endpoint)` so container traffic survives port-preserving SNAT at the boundary. Port-rewriting NAT and DNAT for published container ports are a later phase.
- Owner observations are advisory: an unattributed Flow is still a valid Flow. The product surfaces attribution coverage instead of hiding the remainder.
- `ABI_VERSION` moves to 3; the owner maps and structs join the versioned kernel/user-space contract.
- TCP is captured at connect/listen (`sock_ops`); UDP is captured at send (`cgroup/sendmsg4`) and joined by remote endpoint because that hook has no local port. Container metadata and port-rewriting NAT land in later phases; the join format leaves room for both.
- Listeners that existed before the agent started are seeded from `/proc` once at startup, because `TCP_LISTEN_CB` only fires for new listens.
- Attribution happens at collection time, so a socket created before the agent started has no owner until its next connection.
