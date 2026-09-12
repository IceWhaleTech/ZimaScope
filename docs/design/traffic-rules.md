# Traffic Rules Design

This document is the implementation contract for enforcing Traffic Rules at the
Device Boundary. It complements
[ADR-0004](../adr/0004-traffic-policing.md) and uses the product vocabulary
from `CONTEXT.md`.

## Scope

ZimaScope polices user-confirmed Traffic Rules with eBPF programs inside the
existing TC attachment. It never shapes, queues or delays packets: over-limit
traffic is dropped, so TCP reacts through congestion control and UDP sees loss.

The first phase supports IPv4, the actions `limit` and `block`, the directions
`inbound`, `outbound` and `both`, and two match kinds: an Endpoint (address or
CIDR, optional port) and an Application Identity (container or process). Domain
and single-Flow matches are out of scope. Enforcement precedes accounting: a
packet dropped by a rule is not a Flow and moves no boundary byte counters.
Per-rule counters and global `policy_*` counters are the record, and policy
drops are intentional behavior, never an Observation Gap.

Fail-open is absolute. A packet passes unless an enabled rule explicitly
matches it and the rule's action says drop; every missing fact (no match,
unknown owner, absent state, detached program, unavailable collector) passes
the packet.

## Rule model

A Traffic Rule is persisted in SQLite and compiled to kernel state. The
user-visible fields are:

| Field | Values | Constraints |
| --- | --- | --- |
| `action` | `limit`, `block` | required |
| `direction` | `inbound`, `outbound`, `both` | required; `both` is compiled into both direction map sets |
| `match` | Endpoint, CIDR or Application | exactly one |
| `rate_bytes_per_s` | `u64` | required for `limit`, forbidden for `block`; 4 KiB/s to 10 GiB/s |
| `burst_bytes` | `u64` | derived on creation (`rate × 1s`) and stored; not user-facing in this phase |
| `enabled` | `bool` | disabled rules stay persisted but are not compiled |

`MAX_TRAFFIC_RULES` is 64, matching the `DEFAULT_TRAFFIC_RULE_CAPACITY`
compiled into the eBPF object. The bound keeps the fixed map capacities honest
and the per-packet evaluation bounded.

An Endpoint rule matches the direction-relative remote endpoint, the same side
the Explorer shows: an outbound rule matches the destination, an inbound rule
matches the source. The optional port uses `0` as the wildcard value, which is
safe because TCP/UDP port 0 never appears on the wire. A CIDR rule matches the
remote address with the longest-prefix lookup and carries no port.

An Application rule matches the identity selected in the UI:

- `cont:<container_id>` resolves to the container's cgroup ids (see
  Compilation); every socket the container owns matches.
- `proc:<exe>` and `proc:comm:<comm>` resolve to the 16-byte `comm` the owner
  map records. An identity that exists only as an executable path is matched by
  `comm`, which can over-match processes sharing a name; the UI must disclose
  this at creation.

### Evaluation order

The packet path evaluates tiers in order and the first tier with a match
wins, because specificity is the product's predictability rule:

1. Application Identity: container key first, then process key.
2. Exact Endpoint: address plus port, then address with the wildcard port.
3. CIDR: longest prefix.

Within one tier, `block` beats `limit` when both match (only the application
tier can produce two matches; a map lookup yields at most one entry per key).
Across tiers, the more specific rule wins even when the less specific rule is a
`block`. This interpretation keeps a limited endpoint limited inside a blocked
CIDR, which is the least surprising behavior.

For every matched rule the action is applied per direction. A `both` rule owns
one `RuleState` per direction — a token bucket for `limit`, counters for
`block` — so each direction is capped at the configured rate independently;
the rate is not shared between directions.

## Kernel ABI

`ABI_VERSION` moves to 4. `AbiMetadata` gains `rule_state_size` and
`policy_config_size`, and `KernelStats` gains:

```rust
pub policy_dropped_packets: u64,
pub policy_dropped_bytes: u64,
pub policy_missing_state: u64,
```

The new fixed-size types (all `#[repr(C)]`, size-asserted like the existing
ones):

```rust
pub const DEFAULT_TRAFFIC_RULE_CAPACITY: u32 = 64;

#[repr(u8)]
pub enum RuleAction {
    Limit = 1,
    Block = 2,
}

/// Value stored in every match map.
#[repr(C)]
pub struct RuleRef {
    pub rule_id: u32,
    pub action: u8,
    pub reserved: [u8; 3],
}

/// Token bucket key: one bucket per rule and direction.
#[repr(C)]
pub struct BucketKey {
    pub rule_id: u32,
    pub direction: u8,
    pub reserved: [u8; 3],
}

/// One direction of one rule. Protected by `lock`; user space reads and
/// updates it with `BPF_F_LOCK`.
#[repr(C)]
pub struct RuleState {
    pub lock: bpf_spin_lock,
    pub reserved: u32,
    pub rate_bytes_per_s: u64,
    pub burst_bytes: u64,
    pub tokens: u64,
    pub last_refill_mono_ns: u64,
    pub matched_packets: u64,
    pub matched_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

/// Exact Endpoint match key; zero-extended IPv4 address.
#[repr(C)]
pub struct EndpointMatchKey {
    pub addr: [u8; 16],
    pub port_be: u16,
    pub reserved: [u8; 6],
}

/// Single-entry fast-path configuration.
#[repr(C)]
pub struct PolicyConfig {
    pub enabled: u8,
    pub app_rules: u8,
    pub endpoint_rules: u8,
    pub reserved: u8,
    pub revision: u32,
}
```

CIDR rules key the LPM trie with its packed `{ prefix_len: u32, addr: [u8; 4] }`
layout instead of a named struct.

`RuleState` is the only map value that needs BTF: the kernel requires BTF
description for `bpf_spin_lock` in a map value, so the bucket map is declared
with `#[btf_map]` while the match maps keep the existing legacy declaration
style. The eBPF build must emit BTF (`-Cdebuginfo=2 -Clink-arg=--btf`); the
existing object does not, and adding those flags is part of the first
implementation commit.

New maps, all bounded:

| Map | Type | Key → value | Capacity |
| --- | --- | --- | --- |
| `policy_config` | array | `u32` → `PolicyConfig` | 1 |
| `rule_states` | BTF hash | `BucketKey` → `RuleState` | `2 × MAX_TRAFFIC_RULES` |
| `app_cgroup_ingress` / `app_cgroup_egress` | hash | `u64` → `RuleRef` | `MAX_TRAFFIC_RULES` each |
| `app_comm_ingress` / `app_comm_egress` | hash | `[u8; 16]` → `RuleRef` | `MAX_TRAFFIC_RULES` each |
| `endpoint_exact_ingress` / `endpoint_exact_egress` | hash | `EndpointMatchKey` → `RuleRef` | `MAX_TRAFFIC_RULES` each |
| `endpoint_cidr_ingress` / `endpoint_cidr_egress` | LPM trie | `CidrKey` → `RuleRef` | `MAX_TRAFFIC_RULES` each |

Directions get their own maps instead of a direction field in the key so the
TC program selects its map set once and the key layouts stay minimal.

## Packet path

`zimascope-ebpf/src/policy.rs` owns evaluation; `tc.rs::process` calls it after
parsing and before any Flow accounting:

1. Read `policy_config`; when `enabled == 0`, return pass. This is the
   no-rules fast path: one array lookup per packet.
2. When `app_rules != 0`, build the owner key from the Flow and look up the
   owner map, exactly as the user-space join does:
   outbound uses `local_port = src_port`, remote = destination; inbound uses
   `local_port = dst_port`, remote = source. TCP falls back to the listener
   key; UDP keys carry `local_port = 0` and the remote endpoint. A missing
   owner simply skips the application tier.
3. Check the container and process maps of the packet's direction.
4. When `endpoint_rules != 0`, check the exact map twice (with the packet's
   port, then the wildcard port) and then the CIDR trie.
5. On a match, run the action. `block` drops immediately. `limit` takes the
   rule's `RuleState` and refills/consumes tokens:

```text
now = bpf_ktime_get_ns()
lock(state)
elapsed = now - state.last_refill_mono_ns
if elapsed > 1s: elapsed = 1s            // keeps the multiply inside u64
add = elapsed * state.rate_bytes_per_s / 1_000_000_000
if add > 0:
    tokens = min(state.burst_bytes, state.tokens + add)
    state.tokens = tokens
    state.last_refill_mono_ns = now      // a zero add must not eat credit
state.matched_packets += 1
state.matched_bytes += packet_len
if state.tokens >= packet_len:
    state.tokens -= packet_len
    unlock; pass
else:
    state.dropped_packets += 1
    state.dropped_bytes += packet_len
    unlock; return TC_ACT_SHOT
```

   Refill happens on packet arrival, so no timers or background work exist in
   the kernel. Dropped packets increment `packets_seen`/`packets_parsed`
   because they were observed and parsed, but they never reach `update_flow`
   and never sample domain or service evidence.
6. No match returns pass, preserving the existing `TC_ACT_UNSPEC` contract for
   every packet the policy does not drop.

Every failure path inside evaluation (config read, owner lookup, map lookup,
state lookup) passes the packet and increments `policy_missing_state` only
when state should have existed, so a broken policy degrades to the current
observe-only behavior.

## Compilation and reconciliation

`zimascoped/src/policy/` owns user-space policy:

- `TrafficRule` is the persisted model; `compile(rows, resolver)` turns enabled
  rules into a `CompiledPolicy` (revision, per-tier match entries, per-rule
  state seeds) or an inactive entry with an explanation when a match cannot be
  resolved.
- Container rules resolve `cont:<id>` to cgroup ids by walking
  `/sys/fs/cgroup`, propagating a container id to descendant directories so
  nested cgroups inside the container match too. The walk is cached and
  refreshed on the existing 5-second cgroup-index cadence; when a container
  restarts and its cgroup id changes, the refresh recompiles the affected rule.
  A container with more cgroup directories than the match capacity allows is
  reported unresolved instead of partially matched.
- Process rules resolve `proc:comm:<comm>` directly and `proc:<exe>` through
  the `applications` table's `comm` column; a missing `comm` is unresolved.

Applying a `CompiledPolicy` is diff-based against the previously applied
program. The ordering invariants make every intermediate state fail open:

- Disable first: `policy_config.enabled` is cleared before removals and set
  after additions.
- Adding a rule: insert its `RuleState` before inserting any match entry that
  references it.
- Removing a rule: remove its match entries before removing its `RuleState`.
- Rate or action changes keep the rule id: update `RuleState` parameters
  through `BPF_F_LOCK`, then reconcile match entries.
- The config entry is written last with the new revision, so the reported
  `revision` only advances after the program is fully in place.

A failed operation aborts the remaining diff, keeps the previous revision
reported, and records `last_error`; because operations are ordered, the
worst case is less enforcement, never more.

At startup, `main` starts the Collector, hands the `PolicyHandle` to
`ApiState`, then loads and applies the persisted rules. When collection is
unavailable, rules stay persisted and CRUD still works; their state reads
`unavailable` and nothing is enforced.

## Control path

`Collector` exposes a cloneable `PolicyHandle` that wraps a bounded
`mpsc<PolicyCommand>` channel. The worker's `select!` loop (shutdown, command,
tick) processes commands between polls, so rule changes take effect within one
round trip and never touch the packet path from user space. `KernelSource`
gains `apply_policy(Vec<PolicyOp>)`, `read_config()` and
`read_rule_states(&[BucketKey])`; the deterministic test source records
operations for assertions.

`ApiState` owns the `PolicyEngine` (rule snapshots, compilation, the
background cgroup refresh) and the `PolicyHandle`, injected after the
Collector starts. Rule mutations run under a dedicated apply lock so two
concurrent edits cannot interleave compile and apply.

## Storage

Schema v6 adds:

```sql
CREATE TABLE IF NOT EXISTS traffic_rules (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    direction TEXT NOT NULL,
    match_kind TEXT NOT NULL,
    address TEXT,
    prefix_len INTEGER,
    port INTEGER,
    application_id TEXT,
    rate_bytes_per_s INTEGER,
    burst_bytes INTEGER,
    enabled INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
```

`Settings` gains a `traffic_rules.enabled` master switch (default `true`) that
is applied before any rule diff; turning it off clears `policy_config.enabled`
and leaves the compiled program in place for a fast re-enable.

## API

New resource, following the existing conventions (`limit`/`offset`, problem
details, audit ring):

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/traffic-rules` | List rules with live counters and per-rule state |
| POST | `/v1/traffic-rules` | Create a rule; 422 on validation failure, 409 when the bound is hit |
| GET | `/v1/traffic-rules/{id}` | Rule detail |
| PATCH | `/v1/traffic-rules/{id}` | Enable/disable, change rate, change direction |
| DELETE | `/v1/traffic-rules/{id}` | Remove the rule |

The DTO carries `action`, `direction`, `match` (kind plus the kind's fields),
`rate_bytes_per_s`, `burst_bytes`, `enabled`, timestamps, `counters`
(matched/dropped packets and bytes) and a derived `state`: `active`,
`unresolved`, `bypassed`, or `unavailable`. Mutations write the existing audit
ring (`traffic_rule.create`, `.update`, `.delete`) and the master switch goes
through `PATCH /v1/settings`.

`/v1/status` gains an `enforcement` block: master switch, applied revision,
active rule count, kernel drop counters, and `last_error`. Rules are never
reported as enforced when collection is down.

## Frontend

The Explorer row menu's `Rate limit` and `Block traffic` entries become real
actions: they open a dialog prefilled from the row (connection → remote
endpoint and port; endpoint → address; application → identity) with direction,
rate in Mbps (converted to bytes per second) and an explicit confirmation
before a `block`. Domain rows do not offer Traffic Rule actions because domain
matching is not supported; the reason is disclosed instead of pretending.

Settings gains a `Traffic rules` card: the master switch, the rule list with
per-rule state, counters and enable/disable/delete, and a prominent
"not enforced" state whenever collection or the master switch is off.

## Failure semantics

| Condition | Behavior |
| --- | --- |
| No rules, master switch on | One array lookup per packet; no other policy work |
| Master switch off | `policy_config.enabled = 0`; every packet passes |
| Rule unresolved (container gone, no comm, too many cgroups) | Rule persists, state `unresolved`, no match entries installed |
| Unknown owner or cache miss | Application tier skipped; endpoint tiers still evaluate |
| State entry missing for a match | Packet passes; `policy_missing_state` increments |
| eBPF or collector unavailable | Rules persist, nothing enforced, state `unavailable` |
| Daemon crash or upgrade | tcx links die with the process; no kernel residue; rules replay at next start |

## Required tests

- ABI sizes, alignments, offsets and discriminants for every new struct,
  including `RuleState.lock` at offset 0, plus the `ABI_VERSION = 4` metadata
  mismatch path.
- Compiler tests: endpoint with and without port, port-specific over wildcard
  precedence, CIDR longest prefix, `both` direction expansion, container
  cgroup propagation and refresh after a cgroup id change, `proc:<exe>` →
  `comm` resolution and unresolved identities, rule bound, rate validation.
- Reconciliation tests: fail-open operation ordering, disable-first /
  enable-last, removal order, revision monotonicity, partial-failure recovery.
- API tests: CRUD validation (422/409), audit entries, status enforcement
  block, master switch, counters returned under `BPF_F_LOCK`.
- Linux network-namespace integration: a `limit` rule caps throughput within
  tolerance, a `block` rule passes nothing, drops are absent from Flow bytes,
  fail-open when the master switch is off or the owner is unknown, and
  persistence replays after a restart.
- Performance: baseline versus one matched rule and versus sixty rules, to
  keep the no-rules path at one array lookup and the enabled path within the
  1% CPU budget.

## Open items

- The BTF build flags and aya's support for a `bpf_spin_lock` map value must be
  proven by a load test in the first implementation commit. If the kernel or
  the loader rejects it, the enforcement mechanism changes and ADR-0004 must
  be amended; silently degrading to an approximate limiter is not acceptable.
- IPv6 matches, domain matches, per-rule dynamic rates, and port-rewriting NAT
  for container rules land in later phases. Application rules inherit every
  attribution limit recorded in `application-identity.md` (owner observations
  are advisory, port-rewriting NAT is out, `comm` can over-match).
