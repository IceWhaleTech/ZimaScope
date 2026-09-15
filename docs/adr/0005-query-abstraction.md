---
status: accepted
---

# Separate enforcement selectors from observation queries with a Selector IR and resolver seam

Z-Scope will model what an action targets as a serializable `Selector` intermediate representation, resolve it to bounded kernel-matchable targets through one `EvidenceResolver` trait seam, and compile every action — `limit`, `block`, and future actions such as reserved bandwidth — from the same resolution result. `FlowQuery` stays the observation-side filter: when a user acts on a filtered view, it lowers into a `Selector`, and any dimension the packet path cannot prove (time range, Flow state, association confidence) is rejected with a reason instead of silently ignored. Traits are used at the resolver seam, not as the query abstraction itself: the query language stays a closed enum, so the wire format is serde-stable, persistence is a JSON column, and one capability matrix (`Direct`, `Resolved`, `Unsupported`) is exhaustively compiled and reported. Pre-release breaking changes are accepted: `RuleMatch` is deleted, `traffic_rules` moves to `selector_json`, and rule requests carry `selector`.

## Considered Options

- One shared query type for observation and enforcement (`FlowQuery` everywhere): rejected because the packet path can only prove packet facts; time windows, Flow state, association confidence and enrichment filters would be silently stale or unenforceable, and read concerns (sort, pagination, aggregation) would leak into the kernel contract. FlowQuery keeps growing fields because it is asked to serve both roles; the split stops that growth.
- `trait Query` as the query abstraction: rejected because trait objects cannot be serialized, persisted or exposed over HTTP, and a trait gives no exhaustive capability mapping. Traits belong at the resolver and action seams.
- A string DSL (`app=cont:x and country=CN`) parsed at the edge: rejected because it hides the capability boundary inside a parser, makes persisted rules opaque, and leaves no type-level place for "resolved snapshots expire and must be re-proved".
- Resolve once at rule creation and persist the concrete address list as rules: rejected because containers restart, DNS answers rotate and country assignments move; resolution needs a coverage report plus an expiry and refresh policy tied to evidence lifetime, not one-shot materialization.

## Consequences

- A new control-plane module `zimascoped/src/query/` owns `Selector`, `Resolution`, `Coverage` and the `EvidenceResolver` trait. `policy::compile` consumes resolved targets; `ApplicationKeys` folds into the resolver. `zimascope-common` and `ABI_VERSION` are untouched.
- This phase's `Selector` variants are `Endpoint`, `Cidr` and `Application`. Each declares a kernel plan: `Direct` (targets follow from the selector alone), `Resolved` (targets depend on observed evidence and expire or refresh), or `Unsupported` (rejected at creation with a 422 problem detail). Domain, country and ASN selectors land as `Resolved` variants with expiry and coverage before the UI can offer them.
- Fail-open and capacity semantics are unchanged: resolution yields bounded, deduplicated targets, an unresolved selector leaves its rule persisted but inactive, and no failure path drops a packet. An expired resolution removes match entries instead of enforcing against unproven addresses.
- `FlowQuery` lowers into `Selector` through one fallible conversion that names every unmappable field; `POST /v1/traffic-rules/resolve` reports targets and coverage to the confirmation dialog.
- Reserved bandwidth needs its own ADR because policing cannot guarantee bandwidth (ADR-0004); the closed `ActionSpec` model leaves room for it without touching selector resolution.
- `RuleMatch`, the `match` request field and the per-kind columns leave the schema; `SCHEMA_VERSION` bumps and pre-release databases recreate the rules table. Observation queries stop acquiring enforcement-only fields.
