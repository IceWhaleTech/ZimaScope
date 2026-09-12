---
status: accepted
---

# Enforce user-confirmed Traffic Rules at the Device Boundary with eBPF policing

ZimaScope will enforce user-confirmed Traffic Rules at the Device Boundary by extending its existing TC program with bounded match maps and per-rule token buckets, dropping over-limit packets (policing). A Traffic Rule carries an action (`limit` or `block`), a direction, and one match: an Endpoint (address or CIDR, optional port) or an Application Identity resolved through the owner map (ADR-0003). Policy evaluation runs before Flow accounting, so packets a rule drops are not counted as boundary traffic; per-rule matched and dropped counters are the record instead, and policy drops are never Observation Gaps. The most specific match wins (Application Identity, then exact Endpoint, then CIDR), block beats limit whenever both match, and any missing evidence — no rule match, unknown owner, failed map read or update, detached program — passes the packet. tc qdisc shaping is rejected because queueing delays packets and leaves kernel state that outlives a crashed or upgraded daemon; process-scoped tcx links make policing fail open by construction.

## Considered Options

- eBPF TC policing: selected because it reuses the single TC attachment and parse pass from ADR-0001, keeps rule state in bounded maps, and inherits tcx's process-scoped lifetime: a crash or upgrade removes enforcement with no qdisc or filter left behind.
- tc qdisc shaping (HTB/TBF with filters): rejected. It is the only way to delay rather than drop, but qdiscs and filters are kernel objects that survive daemon death and would need explicit cleanup on exit, upgrade and uninstall, plus rollback when cleanup fails. It also buffers packets, trading the latency and memory profile ZimaScope promises for smoother rates.
- nftables/iptables `hashlimit`: rejected because it adds a second rule language and an external dependency, cannot join Application Identity, and offers only coarse counters.
- Proxy-level limiting through the mihomo control API: rejected as the general mechanism because it covers only proxied traffic and couples enforcement to a third-party process; the control API exposes no per-connection rate control.
- A second eBPF program owned by a separate enforcement engine: rejected because the owner facts live in the Collector's maps; a second object would need pinned maps and a duplicated parse pass, fragmenting the single-Collector contract of ADR-0001.

## Consequences

- `ABI_VERSION` moves to 4. New bounded maps join the kernel/user-space contract: match tables compiled from rules, a per-rule table holding parameters, token-bucket state and counters, and one global enable flag so an installation with no rules adds a single array lookup to each packet.
- Application Identity rules compile to the keys the packet path can prove: `cgroup_id` for containers and `comm` for host processes. Identities that exist only as an executable path are matched by `comm` and the UI must disclose the broader match; port-rewriting NAT and listener seeding inherit the attribution limits recorded in ADR-0003.
- Traffic Rules are a persisted, audited resource: the local API changes them through the Collector's control path, so a change reaches the kernel within one round trip without blocking the packet path. Rules are stored in SQLite and replayed at startup; when eBPF is unavailable the rules remain stored but enforcement is reported as unavailable.
- Enforcement precedes accounting: dropped packets never become Flows or move byte counters, because they did not cross the Device Boundary. Rates are stored as bytes per second to match counters and converted for display; token-bucket burst defaults to one second of the rate and is not user-facing in this phase.
- The first phase is IPv4 only, in lockstep with collection. Domain matching is deliberately absent: with fake-IP proxying a domain rule would only limit the proxy connection, and shared CDN addresses would over-match. Proxied traffic is limited as the proxy's sockets.
- Rule changes require explicit user confirmation and are recorded in the local audit log. The rule count is bounded, and one control disables all enforcement. Limits never restrict the daemon's Unix socket, so the UI that turns them off stays reachable.
- A crash, upgrade or uninstall stops enforcement until the daemon returns, but leaves no residual kernel state. The "no error path may drop, reject, delay, or modify a network packet" rule in the collector design gains a scoped exception: only a matching, enabled Traffic Rule may return `TC_ACT_SHOT`.
