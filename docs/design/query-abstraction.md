# Query Abstraction Design

This document is the implementation contract for ADR-0005. It defines how every
control-plane feature that must locate resources and act on them — Traffic Rules
today, reserved bandwidth and other query-driven actions later — shares one
query vocabulary without coupling to `FlowQuery` or to any single enforcement
mechanism. It uses the product vocabulary from `CONTEXT.md`.

It amends [traffic-rules.md](traffic-rules.md): the rule `match` model becomes
`Selector`, rule identity resolution moves behind the resolver seam, and
`ActionSpec` carries per-action parameters. Everything else in that document —
kernel ABI, token bucket, ordering invariants, fail-open — stays authoritative.

## Scope

In scope:

- One serializable `Selector` IR for "what an action targets".
- One `EvidenceResolver` trait that turns a `Selector` into bounded,
  kernel-matchable targets with a coverage report.
- One `ActionSpec` model so `limit`, `block` and future actions compile from the
  same resolution result.
- Storage, API and frontend changes that carry `selector` end to end.

Out of scope:

- The read side. `FlowQuery` remains the observation filter for Flows,
  Endpoints, Domains, Applications, Connections and exports; it stops growing
  enforcement-only fields. A fallible lowering into `Selector` supports "act on
  this filtered view".
- Kernel changes. `Selector` compiles into the existing `MatchEntry` tiers and
  `RuleState` model from `traffic-rules.md`; new kernel tiers only arrive with
  a future capability that needs them.
- Traits as the query language. The query language is a closed enum so the wire
  contract, persistence and capability mapping stay exhaustive; traits mark the
  resolver seam.

## Selector model

`Selector` lives in a new control-plane module `zimascoped/src/query/` — not in
`zimascope-common`, because the eBPF object consumes compiled match entries, not
selectors.

```rust
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Selector {
    Endpoint {
        address: IpAddr,
        port: Option<u16>,
    },
    Cidr {
        address: IpAddr,
        prefix_len: u8,
    },
    Application {
        /// `cont:<container id>`, `proc:<exe>` or `proc:comm:<comm>`.
        id: String,
    },
}
```

The wire shape is the persisted shape: one JSON object per rule, matching the
existing Application Identity keys. Examples:

```json
{ "kind": "endpoint", "address": "203.0.113.9", "port": 443 }
{ "kind": "cidr", "address": "192.0.2.0", "prefix_len": 24 }
{ "kind": "application", "id": "cont:abc123" }
```

Validation rejects, as a 422 problem detail: port `0`, prefix lengths outside
`1..=32`, empty identities, unspecified/multicast/broadcast addresses, and any
address family the kernel plan marks unsupported.

### Kernel plan

Every selector answers one capability question, and the compiler is the only
place that maps capability to kernel behavior:

```rust
pub enum KernelPlan {
    /// Targets follow from the selector alone and stay valid until the
    /// selector changes.
    Direct,
    /// Targets depend on observed evidence; validity is bounded by a refresh
    /// trigger and/or an expiry.
    Resolved {
        refresh: Refresh,
        expires: bool,
    },
    /// The selector or address family cannot be enforced in this phase.
    Unsupported { reason: &'static str },
}

pub enum Refresh {
    /// Container cgroup ids re-resolve on the existing cgroup-index cadence.
    ContainerIndex,
    /// An executable path resolves to `comm` through the applications table.
    ApplicationsTable,
    /// Domain or enrichment evidence; re-resolve when evidence changes or
    /// expires.
    Evidence,
}
```

`Application` inspects its own id prefix: `proc:comm:` is `Direct`, `cont:` is
`Resolved { refresh: ContainerIndex, .. }`, and `proc:<exe>` is
`Resolved { refresh: ApplicationsTable, .. }`. IPv6 stays
`Unsupported { reason: "IPv6 matching is a later phase" }` in this phase, per
`traffic-rules.md`, while the wire type already accepts `IpAddr`.

## Capability matrix

| Selector | Evidence | Plan | Compiles to | Phase |
| --- | --- | --- | --- | --- |
| `endpoint` | packet five-tuple | Direct | exact match map (port, then wildcard) | now |
| `cidr` | packet address | Direct | LPM trie, longest prefix | now |
| `application` `proc:comm:` | none | Direct | `comm` map | now |
| `application` `cont:` | cgroup tree | Resolved, `ContainerIndex` | cgroup-id map | now |
| `application` `proc:<exe>` | `applications` table | Resolved, `ApplicationsTable` | `comm` map | now |
| `protocol` | packet | Direct | new match tier (kernel change) | later |
| `domain` | `observations` table | Resolved, `Evidence`, expiring | endpoint snapshot | later |
| `country`, `asn`, `organization` | enrichment database | Resolved, `Evidence`, expiring | aggregated CIDRs, capacity-gated | later |
| `range`, `state`, `has_domain`, `evidence`, `confidence`, `q`, `sort`, `limit`, `offset` | none | Unsupported | — | never (observation-only) |

`Unsupported` is a product answer, not an implementation detail: the API names
the selector and the reason, and the UI explains why the action is unavailable
instead of offering a rule that silently under-enforces.

## Resolution

### Evidence resolver

The trait separates "find the resources" from "act on the resources":

```rust
pub trait EvidenceResolver {
    fn resolve(
        &mut self,
        selector: &Selector,
        context: &ResolveContext,
    ) -> Result<Resolution, ResolveError>;
}

pub struct ResolveContext {
    pub now: SystemTime,
}
```

Every selector goes through the resolver for uniformity; `Direct` variants need
no external evidence and move straight through. The system implementation
composes the existing evidence sources: the cgroup index
(`zimascoped/src/cgroup.rs`), the `applications` table, and — as later variants
land — the `observations` table and the enrichment database. `ApplicationKeys`
(`zimascoped/src/policy/resolve.rs`) is absorbed into this resolver rather than
kept as a second seam.

The resolver owns selector → target conversion. The policy compiler owns
targets + action → kernel program. Feature code owns neither and never queries
storage directly.

### Targets and coverage

```rust
pub struct Resolution {
    pub targets: Vec<MatchTarget>,
    pub coverage: Coverage,
    pub expires_at: Option<SystemTime>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MatchTarget {
    Endpoint { address: Ipv4Addr, port: Option<u16> },
    Cidr { address: Ipv4Addr, prefix_len: u8 },
    AppCgroup { cgroup_id: u64 },
    AppComm { comm: [u8; 16] },
}

pub enum Coverage {
    Complete,
    /// The rule persists but installs no match entries.
    Unresolved { reason: String },
}

pub enum ResolveError {
    /// The resolver itself failed (database, cgroup walk); retried on the
    /// next refresh trigger.
    Unavailable { reason: String },
}
```

Targets are deduplicated and deterministically ordered before compilation, so
re-resolution produces identical programs when nothing changed and the diff is
empty. Capacity is checked exactly as in `traffic-rules.md`: any match tier
holding more entries than the kernel capacity makes the whole rule unresolved,
never partially installed. `Coverage` has no `Partial` state in this phase;
aggregation strategies for large evidence sets are an open item.

### Validity and refresh

`Direct` resolutions are valid until the rule changes. `Resolved` resolutions
carry the earliest contributing evidence expiry in `expires_at` and are
re-resolved when:

- the rule or the master switch changes (existing `apply_policy` path),
- the refresh trigger fires: cgroup-index cadence for `ContainerIndex`,
  application-record updates for `ApplicationsTable`, new or expiring
  observations for `Evidence`,
- `expires_at` passes (backstop sweep),
- the collector restarts (rules replay, as today).

An expired resolution deactivates its rule — match entries are removed so the
rule reports `unresolved`/`stale` — rather than enforcing against addresses
that are no longer proven. This keeps the apply invariant "the worst case is
less enforcement, never more" intact for `block` as well as `limit`, and honors
the fail-open rule: unproven targets pass.

## Intent and actions

```rust
pub enum ActionSpec {
    Limit { rate_bytes_per_s: u64, burst_bytes: u64 },
    Block,
}

pub struct TrafficRule {
    pub id: u32,
    pub action: ActionSpec,
    pub direction: RuleDirection,
    pub selector: Selector,
    pub enabled: bool,
}
```

`ActionSpec` is a closed enum; a new action is a product decision with its own
kernel representation, not a plugin. Per-action validation replaces the
current combined check: `Limit` validates the rate range and burst, `Block`
forbids a rate, and selector validation always runs first so unsupported
selectors fail with the selector reason.

| Action | Kernel `RuleAction` | State seed | Notes |
| --- | --- | --- | --- |
| `Limit` | `Limit` | token bucket per rule-direction | policing only (ADR-0004) |
| `Block` | `Block` | none | — |
| `Reserve` (future) | new | new | requires an ADR; policing cannot reserve bandwidth |

### Compilation pipeline

```text
TrafficRule → validate action + selector plan
            → EvidenceResolver::resolve → Resolution
            → compile targets per action → CompiledRule / CompiledPolicy
            → diff against the applied program → PolicyOp sequence
```

`compile` becomes:

```rust
pub fn compile(
    rules: &[TrafficRule],
    resolver: &mut dyn EvidenceResolver,
    revision: u64,
    enabled: bool,
) -> Result<CompiledProgram, String>
```

Ordering, revision, disable-first/enable-last and partial-failure rules from
`traffic-rules.md` are unchanged. `MatchTarget` → `MatchEntry`, action →
`RuleAction`, and state seeding happen in `policy`, where the kernel contract
already lives. `UnresolvedRule` keeps its meaning and gains the resolution
reason.

## Observation query lowering

`FlowQuery` gets one fallible conversion, used by "act on this view" entry
points and by exports that want to explain why a filter is not enforceable:

```rust
impl TryFrom<&FlowQuery> for Selector {
    type Error = UnsupportedQuery;
}

pub struct UnsupportedQuery {
    pub fields: Vec<&'static str>,
    pub reason: String,
}
```

Mapping rules:

- `ip`, `src_ip`, `dst_ip` plus optional `port` → `Endpoint`.
  `src_ip` and `dst_ip` are address fields; a query that sets both does not
  compose in this phase and is rejected.
- `application_id` → `Application`.
- `direction` is not part of the selector; it becomes the rule direction
  (`inbound`/`outbound`, `Both` when the query has none).
- `range`, `state`, `has_domain`, `evidence`, `confidence`, `q`, `hide_noise`,
  `scope`, `exclude_scope`, `protocol`, `sort`, `limit`, `offset` →
  unsupported, listed by name in the 422 problem detail.
- Future `domain`, `country`, `asn`, `organization` map to `Resolved`
  selectors once they land.

The frontend's existing row actions keep sending a single-criterion selector
and are unaffected by lowering. Multi-criterion composition (`All`/`Any`) is an
open item; this phase supports exactly one selector per rule.

## Storage

`SCHEMA_VERSION` moves from 6 to 7. The rules table becomes:

```sql
CREATE TABLE IF NOT EXISTS traffic_rules (
    id INTEGER PRIMARY KEY,
    action TEXT NOT NULL,
    direction TEXT NOT NULL,
    selector_json TEXT NOT NULL,
    rate_bytes_per_s INTEGER,
    burst_bytes INTEGER,
    enabled INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
```

Pre-release databases recreate the table on the version bump; no row migration
is written. `selector_json` is canonical and `action` stays a queryable column
for listing. `rules_revision` still advances on every mutation and is the
recompile trigger.

## API

Rule DTOs and request bodies speak `selector`:

```json
POST /v1/traffic-rules
{
  "action": "limit",
  "direction": "outbound",
  "selector": { "kind": "application", "id": "cont:abc123" },
  "rate_bytes_per_s": 1048576
}
```

- `CreateTrafficRuleRequest` / `UpdateTrafficRuleRequest` replace `match` with
  `selector`; `deny_unknown_fields` stays.
- `TrafficRuleDto` exposes `selector` (the serde `Selector`), `action`,
  `direction`, `rate_bytes_per_s`, `burst_bytes`, `enabled`, `state`,
  `state_reason`, timestamps and counters.
- `POST /v1/traffic-rules/resolve` is a preflight for the confirmation dialog:
  request `{ direction, selector }`, response
  `{ plan: "direct" | "resolved", targets: [...], coverage, reason, expires_at }`.
  It resolves only; it persists and enforces nothing. The preflight applies the
  same per-tier capacity bound as compilation, so `complete` means the rule
  would compile as shown.
- 422 validation failures name the selector kind, the offending field and the
  reason (`unsupported`, `unresolved`, `invalid`). The existing audit entries
  (`traffic_rule.create`, `.update`, `.delete`) are unchanged.

## Frontend

- `types.ts` replaces `TrafficRuleMatchInput` with a discriminated
  `TrafficRuleSelector` union that mirrors the serde shape.
- Explorer row menus build a `Selector`: Connection → `endpoint` with address
  and port, Endpoint → `endpoint` without port, Application → `application`.
- The confirmation dialog may call `/v1/traffic-rules/resolve` to show what
  will be enforced; `Direct` selectors show their target count, `Resolved`
  selectors show coverage and expiry.
- Settings renders selector kind and parameters instead of the per-kind match
  fields.

## Failure semantics

| Condition | Behavior |
| --- | --- |
| Unsupported selector at creation | 422 problem detail; nothing persisted |
| Unresolved selector (`cont:` gone, no `comm`) | Rule persists, state `unresolved`, no match entries |
| Resolved evidence expired before refresh | Match entries removed, state `unresolved`, re-resolve scheduled |
| Resolver unavailable (database error) | Rule keeps its persisted selector, state `unresolved` |
| Capacity overflow | Whole rule unresolved, never partially installed |
| Collector unavailable | Rules persist, nothing enforced, state `unavailable` |
| Rule, action or selector change | Recompile and reapply through the existing `PolicyHandle` round trip |
| Daemon crash or upgrade | tcx links die with the process; rules replay at next start |

## Implementation order

1. Add `zimascoped/src/query/` with `Selector`, `KernelPlan`, `Resolution`,
   `MatchTarget`, `Coverage` and the `EvidenceResolver` trait, plus tests.
   No behavior change.
2. Rewrite `policy` to consume `ActionSpec` + `Selector`: delete `RuleMatch`,
   move identity resolution into the resolver, change `compile`'s signature.
3. Switch storage, DTOs and handlers to `selector_json` and the preflight
   endpoint; schema version 7.
4. Switch the frontend types and rule dialogs; add preflight to confirmation.
5. Align `traffic-rules.md` with the new match model and update `/v1/status`
   if the enforcement block gains resolution coverage.

## Required tests

- Selector wire tests: serde round trip per variant, unknown kind rejection,
  port/prefix/identity validation, IPv6 rejection with the phase reason.
- Capability tests: `kernel_plan` per application id form, per address family.
- Resolver tests: `cont:` cgroup propagation and refresh after a cgroup-id
  change, `proc:<exe>` → `comm`, `proc:comm:` passthrough, empty resolution,
  capacity overflow, deterministic dedup order, expired evidence.
- Compiler tests: migrated endpoint/CIDR/application cases, `ActionSpec`
  validation, unresolved reason propagation, ordering invariants unchanged.
- Lowering tests: each supported `FlowQuery` mapping, direction mapping,
  unsupported fields named, multi-criterion rejection.
- Storage tests: selector JSON round trip, schema bump recreation.
- API tests: create/update/list with selectors, 422 reasons, preflight targets
  and coverage, audit entries, status.
- Frontend: types compile against the selector union; dialog preflight.

## Open items

- Reserved bandwidth: queueing or scheduling conflicts with ADR-0004 policing.
  A separate ADR must decide the enforcement mechanism before an
  `ActionSpec::Reserve` exists.
- Composition: `All`/`Any` selectors and multi-criterion `FlowQuery` lowering;
  the kernel packet path currently evaluates tiers as alternatives, not
  conjunctions.
- Large resolved sets: country/ASN selectors can exceed the 64-entry kernel
  capacity; aggregation into CIDRs, a wider capacity, or a `Partial` coverage
  state are candidates.
- Refresh ownership: who schedules re-resolution of `Resolved` selectors when
  evidence changes, and how the UI reports staleness.
- Naming: keep `Selector` distinct from the axum `Query` extractor; a future
  refactor may express list endpoints as `Selector` plus view options.
