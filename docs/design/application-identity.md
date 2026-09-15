# Application Identity Design

This document is the implementation contract for attributing Application
Identity to Flows. It complements [ADR-0003](../adr/0003-application-identity.md).

## Scope

An **Application Identity** is the process or workload associated with a Flow
when the system has sufficient evidence. The boundary Flow remains the only
source of packets and bytes; identity is attached as metadata. TCP is captured
through `sock_ops`; UDP through `cgroup/sendmsg4`. Container detection works
for port-preserving SNAT; container metadata (names, images) and port-rewriting
NAT are later phases.

## Capture

A cgroup `sock_ops` program (`sock_owner_v1`, attached at the cgroup v2 root
through an independent `bpf_link`) writes two maps:

| Map | Key | Written on | Meaning |
| --- | --- | --- | --- |
| `owner_map` | `OwnerKey` with `kind = socket` | `TCP_CONNECT_CB` | The process that created an outbound TCP socket |
| `listener_map` | `OwnerKey` with `kind = listener` | `TCP_LISTEN_CB` | The process that owns a listening port |

A second, independent program (`udp_owner_v1`, `cgroup/sendmsg4`, also
attached at the root) writes `owner_map` for every UDP send. Because that
hook exposes no stable local port, UDP keys carry `local_port_be = 0` and the
remote endpoint only.

Both keys are:

```text
remote_addr[16] | remote_port_be | local_port_be | protocol | kind | ip_family | reserved
```

The local address is deliberately excluded: a container's socket tuple uses
the container address, while the same Flow at the boundary carries the
host address after SNAT. `MASQUERADE` normally preserves the source port, so
`(protocol, local_port, remote)` still identifies the connection. The
`kind = listener` key carries no remote address; it attributes every Flow
whose local port is that listener port.

`OwnerValue` carries `tgid`, `pid`, `uid`, `cgroup_id`, the 16-byte `comm` and
`observed_mono_ns`. `comm` is captured in the kernel so a process that exits
before the next poll still has a name. Values are bounded by LRU capacity; a
failed insert increments `owner_events_dropped`.

Listeners that existed before the agent started never emit `TCP_LISTEN_CB`,
so startup seeds the listener cache with one `/proc/net/tcp` +
`/proc/<pid>/fd` sweep. The same sweep covers bound UDP ports from
`/proc/net/udp` and `/proc/net/udp6`: inbound datagrams to a local UDP service
have no `sendmsg4` event of their own, so the listener entry is their only
evidence. The sweep repeats every 20 s because owner entries expire.

## Join

`KernelSource::visit_owners` publishes both maps once per poll. `FlowTracker`
caches owners by their key and resolves every Flow by direction:

- outbound: local port = `source.port`, remote = `destination`;
- inbound: local port = `destination.port`, remote = `source`.

The socket map is tried first (exact connection), then, for UDP, the
remote-only key, then the listener map (local port only). Resolution happens
when the Flow is first observed and rides every later `FlowUpdate` of that
Flow. Owners that arrive in a later poll than the Flow still resolve, because
the cache outlives the poll.

An unattributed Flow carries `application = None`. Attribution coverage is
derived downstream as `attributed / total`; it is never fabricated.

## Enrichment

The database layer resolves an owner into a stable application record:

- identity key: `cont:<container_id>` when a container is identified, else
  `proc:<executable path>`, falling back to `proc:comm:<comm>`;
- display name: container name, then executable basename, then `comm`;
- executable path from `/proc/<tgid>/exe`, uid from the kernel observation,
  container id from `/proc/<tgid>/cgroup` (patterns `docker-<hex>.scope`,
  `cri-containerd-<id>.scope`, `crio-<id>.scope`).

Resolution is best-effort and cached; a process that exited between
collection and ingest still contributes `comm` and `uid`.

## Kernel quirks verified on device

- `bpf_sock_ops.local_port` is the host-order `skc_num`; convert with
  `to_be()` before storing an `_be` field.
- `bpf_sock_ops.remote_port` is `bswap16(skc_dport) << 16` on little-endian
  targets (see `bpf_sock_ops_convert_ctx_access`); take the high 16 bits to
  get the network-order port.
- `bpf_sock_addr.user_port` is the network-order `sin_port` zero-extended, so
  the low 16 bits are already the `_be` value.
- Under tcx multiprog, `TC_ACT_OK` stops the chain. TC programs must return
  `TC_ACT_UNSPEC` to let other classifiers on the same interface run; when
  ZimaScope is the last program the kernel treats it as pass.
- `cgroup_bpf_link_attach` rejects nonzero attach flags, so the cgroup attach
  uses `CgroupAttachMode::Single` (flags 0); links coexist without replacing
  programs owned by other tools.

## Storage

Schema v4 adds `applications` (identity key, kind, display name, exe, comm,
uid, container fields, first/last seen) and `flows.app_id`. Each Flow delta is
also added to `entity_buckets` with `kind = 'application'`, so application
timelines use the existing bucket machinery without new aggregation code.

Schema v11 adds `flows.dst_scope`, the destination address class computed at
ingest. Flows that stay unattributed because they are inbound LAN
multicast/broadcast carry `unattributed_reason = "lan_broadcast"` on the API
(Flow, Connection and per-entity Application usage); the remainder is
explained, never attributed to an Application. Databases upgraded from v10
backfill the column with the same Rust classifier.
