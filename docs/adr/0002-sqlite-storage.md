---
status: accepted
---

# Store Flow history in SQLite behind a thin SQL layer

ZimaScope will persist and query Flow history with SQLite accessed through `rusqlite` (bundled), not an ORM. The API read model is a small SQL schema: `flows`, `observations`, `traffic_buckets`, `settings`, `exports`. Dynamic filtering, sorting, aggregation, timeline bucketing, and pagination are expressed as SQL instead of hand-written in-memory indexes.

## Considered Options

- SQLite + `rusqlite` with raw SQL: selected because the workload is append/upsert plus analytical reads (dynamic predicates, GROUP BY aggregates, Top-N, time buckets). These are exactly the queries an ORM does not simplify, while SQLite keeps a zero-operations local file with WAL, bounded memory, and `:memory:` tests.
- `SQLx` with compile-time checked queries: viable, but it requires an async connection pool and macro-time database access for a single-file, single-writer embedded store. The agent already serializes writes; the pool adds runtime and build complexity without reducing query code.
- SeaORM / Diesel: rejected. The schema is small and the write path has no relational graph, so entity/relationship boilerplate has little to remove. Dynamic filters, aggregates, timeline buckets, cursor/offset windows and exports still require SQL or SQL fragments, leaving two query styles to maintain. SeaORM additionally pulls a large dependency tree (SQLx + sea-query) into a daemon with hard CPU/RSS budgets.
- Keep the in-memory read model only: rejected because PRD 11 requires retention, history, and disk quota; losing history on restart is not acceptable, and the in-memory query engine duplicated what SQL already provides.

## Consequences

- `zimascope-agent/src/api/db.rs` owns schema creation, migrations (`PRAGMA user_version`), ingestion, and queries. The HTTP contract does not depend on the storage engine.
- Writes are grouped in one transaction per collection interval; reads use the same single connection behind a mutex. Queries are local and indexed; any future long-running read must move off the request path.
- Pagination uses `limit` + `offset` with a deterministic tie-breaker (`id` or address). Cursor pagination was dropped as unnecessary for bounded, local data and to keep one pagination implementation.
- Flows keep their Associated Domains as a serialized JSON array and are queried with SQLite JSON functions (`json_each`, `instr`). This avoids a join table while keeping filters exact.
- The user-space model enables the optional `serde` feature so wire enums (`direction`, `evidence`, `scope`, ...) derive directly from domain enums instead of hand-written name mappings.
