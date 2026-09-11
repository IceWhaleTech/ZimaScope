//! SQLite-backed storage and read model for the local API (ADR-0002).
//!
//! One connection behind the API mutex owns schema, ingestion and queries.
//! Writes are grouped in a transaction per collection interval; reads are
//! local, indexed, and bounded by offset pagination. The HTTP contract does
//! not depend on this engine.

use std::{
    collections::VecDeque,
    net::IpAddr,
    num::NonZeroUsize,
    path::PathBuf,
    time::{Duration, Instant, SystemTime},
};

use hashbrown::{HashMap, HashSet};
use rusqlite::{Connection, OptionalExtension, Row, params, params_from_iter, types::Value};
use zimascope_common::model::{
    AddressScope, AssociationConfidence, CollectionBatch, CollectorHealth, DomainEvidence,
    DomainObservation, Endpoint, FlowDirection, FlowKey, FlowState, FlowUpdate, TrafficCounters,
};

#[cfg(test)]
use crate::enrichment::GeoIpDatabase;
use crate::enrichment::{DEFAULT_CACHE_CAPACITY, Enricher, EnrichmentStats};

use super::dto::{
    AsnCountDto, CollectorHealthDto, CountersDto, CountryCountDto, CreateExportRequest,
    DirectionTotalsDto, DomainAddressDto, DomainDetailDto, DomainObservationDto, DomainRefDto,
    DomainSummaryDto, DomainVisibilityDto, EndpointDetailDto, EndpointDto, EndpointSummaryDto,
    EvidenceCountDto, ExportFormat, ExportTaskDto, FlowDto, FlowQuery, IpProfileDto, OverviewDto,
    Page, PortUsageDto, RateDto, TickDto, TickTrafficDto, TimeRange, TimelineDto, TimelinePointDto,
    enum_from_value, enum_value, flow_state_name, unix_millis,
};
use super::error::ApiError;
use super::settings::Settings;

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        ApiError::internal(format!("storage error: {error}"))
    }
}

const EXPORT_MAX_RECORDS: usize = 10_000;
const MAX_DOMAIN_CANDIDATES: usize = 8;
const TOP_LIST_LIMIT: usize = 10;
const AUDIT_CAPACITY: usize = 32;
const MINUTE_BUCKET_RETENTION_MS: i64 = 2 * 60 * 60 * 1000;
const HOUR_BUCKET_RETENTION_MS: i64 = 8 * 24 * 60 * 60 * 1000;
const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;

const SCHEMA_VERSION: i64 = 1;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    direction TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_addr TEXT NOT NULL,
    src_port INTEGER,
    dst_addr TEXT NOT NULL,
    dst_port INTEGER,
    ifindex INTEGER NOT NULL,
    interface TEXT,
    packets INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL,
    state TEXT NOT NULL,
    end_reason TEXT,
    remote_addr TEXT NOT NULL,
    remote_port INTEGER,
    remote_scope TEXT NOT NULL,
    remote_country TEXT,
    remote_region TEXT,
    remote_city TEXT,
    remote_asn INTEGER,
    remote_org TEXT,
    remote_db_version TEXT,
    remote_enriched_at_ms INTEGER NOT NULL,
    domains_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen_ms);
CREATE INDEX IF NOT EXISTS idx_flows_remote ON flows(remote_addr);
CREATE INDEX IF NOT EXISTS idx_flows_state ON flows(state);

CREATE TABLE IF NOT EXISTS observations (
    domain TEXT NOT NULL,
    address TEXT NOT NULL,
    evidence TEXT NOT NULL,
    confidence TEXT NOT NULL,
    last_observed_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    PRIMARY KEY (domain, address, evidence)
);
CREATE INDEX IF NOT EXISTS idx_observations_address ON observations(address);
CREATE INDEX IF NOT EXISTS idx_observations_expires ON observations(expires_at_ms);

CREATE TABLE IF NOT EXISTS traffic_buckets (
    resolution TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    in_packets INTEGER NOT NULL,
    in_bytes INTEGER NOT NULL,
    out_packets INTEGER NOT NULL,
    out_bytes INTEGER NOT NULL,
    PRIMARY KEY (resolution, start_ms)
);

CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    json TEXT NOT NULL,
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS exports (
    id TEXT PRIMARY KEY,
    format TEXT NOT NULL,
    range TEXT,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    record_count INTEGER NOT NULL,
    truncated INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    content BLOB NOT NULL
);
"#;

const FLOW_COLUMNS: &str = "id, direction, protocol, src_addr, src_port, dst_addr, dst_port, \
     ifindex, interface, packets, bytes, first_seen_ms, last_seen_ms, state, end_reason, \
     remote_addr, remote_port, remote_scope, remote_country, remote_region, remote_city, \
     remote_asn, remote_org, remote_db_version, remote_enriched_at_ms, domains_json";

/// Runtime configuration for the API state.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub version: String,
    pub flow_capacity: usize,
    pub export_ttl: Duration,
    pub geoip_database: Option<PathBuf>,
    /// SQLite file; `None` keeps a private in-memory database.
    pub database: Option<PathBuf>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            flow_capacity: 65_536,
            export_ttl: Duration::from_secs(24 * 60 * 60),
            geoip_database: None,
            database: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Rates {
    inbound_bps: u64,
    outbound_bps: u64,
}

#[derive(Clone, Copy, Debug)]
struct AuditEntry {
    at: SystemTime,
    action: &'static str,
    outcome: &'static str,
}

/// One collection interval prepared for SSE subscribers.
pub(crate) struct StreamEvent {
    pub sequence: u64,
    pub collected_at: SystemTime,
    pub interval: Duration,
    pub inbound: TrafficCounters,
    pub outbound: TrafficCounters,
    pub inbound_bps: u64,
    pub outbound_bps: u64,
    pub flows: Vec<FlowDto>,
    pub domains: Vec<DomainObservationDto>,
    pub health: CollectorHealthDto,
}

impl StreamEvent {
    /// Projects the interval into a filtered `tick` payload.
    pub(crate) fn tick(&self, filter: &super::dto::StreamFilter) -> TickDto {
        TickDto {
            sequence: self.sequence,
            collected_at: unix_millis(self.collected_at),
            interval_ms: self.interval.as_millis() as u64,
            traffic: TickTrafficDto {
                inbound_bps: self.inbound_bps,
                outbound_bps: self.outbound_bps,
                inbound: CountersDto {
                    packets: self.inbound.packets,
                    bytes: self.inbound.bytes,
                },
                outbound: CountersDto {
                    packets: self.outbound.packets,
                    bytes: self.outbound.bytes,
                },
            },
            flows: self
                .flows
                .iter()
                .filter(|flow| filter.matches(flow))
                .cloned()
                .collect(),
            domains: self
                .domains
                .iter()
                .filter(|domain| filter.matches_domain(&domain.domain))
                .cloned()
                .collect(),
            health: Some(self.health.clone()),
        }
    }
}

pub(crate) struct ExportContent {
    pub content_type: String,
    pub file_name: String,
    pub bytes: Vec<u8>,
}

/// SQLite connection plus live state that does not belong in the database.
pub(crate) struct Db {
    conn: Connection,
    enricher: Enricher,
    enrichment_error: Option<String>,
    database_error: Option<String>,
    interfaces: HashMap<u32, Box<str>>,
    health: Option<CollectorHealth>,
    last_batch_at: Option<SystemTime>,
    last_interval: Duration,
    batch_sequence: u64,
    rates: Rates,
    audit: VecDeque<AuditEntry>,
    export_counter: u64,
    export_ttl: Duration,
    flow_capacity: usize,
}

impl Db {
    pub(crate) fn open(config: &ApiConfig) -> anyhow::Result<Self> {
        let conn = match &config.database {
            Some(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                Connection::open(path)?
            }
            None => Connection::open_in_memory()?,
        };
        Self::from_connection(conn, config)
    }

    fn from_connection(conn: Connection, config: &ApiConfig) -> anyhow::Result<Self> {
        let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;

        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < SCHEMA_VERSION {
            conn.execute_batch(SCHEMA_SQL)?;
            conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }

        let mut enricher =
            Enricher::new(NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).expect("non-zero capacity"));
        let mut enrichment_error = None;
        if let Some(path) = &config.geoip_database {
            if let Err(error) = enricher.load_database(path) {
                enrichment_error = Some(format!("{error:#}"));
            }
        }

        Ok(Self {
            conn,
            enricher,
            enrichment_error,
            database_error: None,
            interfaces: HashMap::new(),
            health: None,
            last_batch_at: None,
            last_interval: Duration::from_secs(1),
            batch_sequence: 0,
            rates: Rates::default(),
            audit: VecDeque::new(),
            export_counter: 0,
            export_ttl: config.export_ttl,
            flow_capacity: config.flow_capacity.max(1),
        })
    }

    // ----------------------------------------------------------------- ingest

    pub(crate) fn ingest(&mut self, batch: CollectionBatch, settings: &Settings) -> StreamEvent {
        let sequence = batch.sequence;
        let collected_at = batch.collected_at;
        let interval = batch.interval;
        let health = CollectorHealthDto::from_health(&batch.health);
        match self.try_ingest(batch, settings) {
            Ok(event) => event,
            Err(error) => {
                eprintln!("zimascope-agent: storage ingest failed: {error}");
                self.database_error = Some(error.to_string());
                StreamEvent {
                    sequence,
                    collected_at,
                    interval,
                    inbound: TrafficCounters::default(),
                    outbound: TrafficCounters::default(),
                    inbound_bps: self.rates.inbound_bps,
                    outbound_bps: self.rates.outbound_bps,
                    flows: Vec::new(),
                    domains: Vec::new(),
                    health,
                }
            }
        }
    }

    fn try_ingest(
        &mut self,
        batch: CollectionBatch,
        settings: &Settings,
    ) -> Result<StreamEvent, ApiError> {
        let now_instant = Instant::now();
        let now_system = SystemTime::now();
        let CollectionBatch {
            sequence,
            collected_at,
            interval,
            flows,
            domains,
            health,
        } = batch;

        self.batch_sequence = sequence;
        self.last_batch_at = Some(collected_at);
        self.last_interval = interval;
        let health_dto = CollectorHealthDto::from_health(&health);
        for interface in &health.attached_interfaces {
            self.interfaces
                .insert(interface.ifindex.get(), interface.name.clone());
        }
        self.health = Some(health);

        let mut inbound = TrafficCounters::default();
        let mut outbound = TrafficCounters::default();
        for flow in &flows {
            match flow.key.direction {
                FlowDirection::Inbound => add_counters(&mut inbound, flow.delta),
                FlowDirection::Outbound => add_counters(&mut outbound, flow.delta),
            }
        }
        let seconds = interval.as_secs_f64();
        let seconds = if seconds > 0.0 { seconds } else { 1.0 };
        self.rates = Rates {
            inbound_bps: (inbound.bytes as f64 / seconds) as u64,
            outbound_bps: (outbound.bytes as f64 / seconds) as u64,
        };

        let mut touched: Vec<u64> = Vec::new();
        let mut domain_events: Vec<DomainObservationDto> = Vec::new();
        let mut changed_addresses: HashSet<IpAddr> = HashSet::new();

        {
            let tx = self.conn.transaction()?;
            for observation in &domains {
                if store_observation(&tx, observation, now_instant, now_system)? {
                    changed_addresses.insert(observation.address);
                    domain_events.push(DomainObservationDto {
                        domain: normalize_domain(&observation.domain),
                        address: observation.address.to_string(),
                        evidence: observation.evidence,
                        confidence: observation.confidence,
                        observed_at: unix_millis(instant_to_system(
                            observation.observed_at,
                            now_instant,
                            now_system,
                        )),
                    });
                }
            }

            for address in changed_addresses {
                let domains_json = associate_address(&tx, address, now_system)?;
                tx.execute(
                    "UPDATE flows SET domains_json = ?1 WHERE remote_addr = ?2",
                    params![domains_json, address.to_string()],
                )?;
                let mut statement = tx.prepare("SELECT id FROM flows WHERE remote_addr = ?1")?;
                let ids = statement
                    .query_map([address.to_string()], |row| row.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                touched.extend(ids.into_iter().map(|id| id as u64));
            }

            for update in flows {
                let id = flow_id(&update.key);
                upsert_flow(
                    &tx,
                    id,
                    &update,
                    now_instant,
                    now_system,
                    &mut self.enricher,
                    &self.interfaces,
                )?;
                touched.push(id);
            }

            add_bucket(
                &tx,
                "minute",
                truncate_time(collected_at, 60),
                inbound,
                outbound,
            )?;
            add_bucket(
                &tx,
                "hour",
                truncate_time(collected_at, 3600),
                inbound,
                outbound,
            )?;
            tx.commit()?;
        }

        self.enforce_policy(settings, now_system)?;

        touched.sort_unstable();
        touched.dedup();
        let mut updated = Vec::new();
        for id in touched {
            if let Some(dto) = self.flow_by_id(id)? {
                updated.push(dto);
            }
        }

        Ok(StreamEvent {
            sequence,
            collected_at,
            interval,
            inbound,
            outbound,
            inbound_bps: self.rates.inbound_bps,
            outbound_bps: self.rates.outbound_bps,
            flows: updated,
            domains: domain_events,
            health: health_dto,
        })
    }

    fn enforce_policy(&mut self, settings: &Settings, now: SystemTime) -> Result<(), ApiError> {
        self.flow_capacity = settings.resources.max_flow_entries as usize;
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM flows", [], |row| row.get(0))?;
        let overflow = count - self.flow_capacity as i64;
        if overflow > 0 {
            self.conn.execute(
                "DELETE FROM flows WHERE id IN (SELECT id FROM flows ORDER BY last_seen_ms ASC LIMIT ?1)",
                [overflow],
            )?;
        }

        let now_ms = unix_millis(now);
        if settings.history.enabled {
            let cutoff = now_ms - settings.history.retention_days as i64 * MS_PER_DAY;
            self.conn.execute(
                "DELETE FROM flows WHERE state = 'ended' AND last_seen_ms < ?1",
                [cutoff],
            )?;
        } else {
            self.conn
                .execute("DELETE FROM flows WHERE state = 'ended'", [])?;
        }
        self.conn.execute(
            "DELETE FROM observations WHERE expires_at_ms <= ?1",
            [now_ms],
        )?;
        self.conn.execute(
            "DELETE FROM traffic_buckets WHERE resolution = 'minute' AND start_ms < ?1",
            [now_ms - MINUTE_BUCKET_RETENTION_MS],
        )?;
        self.conn.execute(
            "DELETE FROM traffic_buckets WHERE resolution = 'hour' AND start_ms < ?1",
            [now_ms - HOUR_BUCKET_RETENTION_MS],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------------ flows

    pub(crate) fn list_flows(&self, query: &FlowQuery) -> Result<Page<FlowDto>, ApiError> {
        let limit = page_limit(query.limit)?;
        let offset = query.offset.unwrap_or(0);
        let (items, total) = self.flows_page(query, limit, offset)?;
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    pub(crate) fn get_flow(&self, id: &str) -> Result<FlowDto, ApiError> {
        let id = u64::from_str_radix(id, 16)
            .map_err(|_| ApiError::bad_request(format!("invalid Flow id: {id}")))?;
        self.flow_by_id(id)?
            .ok_or_else(|| ApiError::not_found(format!("no Flow with id {id:016x}")))
    }

    fn flow_by_id(&self, id: u64) -> Result<Option<FlowDto>, ApiError> {
        let sql = format!("SELECT {FLOW_COLUMNS} FROM flows WHERE id = ?1");
        self.conn
            .query_row(&sql, [id as i64], flow_dto_from_row)
            .optional()
            .map_err(Into::into)
    }

    fn flows_page(
        &self,
        query: &FlowQuery,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<FlowDto>, usize), ApiError> {
        let now = SystemTime::now();
        let total = self.count_flows(query, now)?;
        let (clauses, params) = self.flow_clauses(query, now, "", true);
        let order = flow_order(query.sort.as_deref())?;
        let sql = format!(
            "SELECT {FLOW_COLUMNS} FROM flows {} ORDER BY {order} LIMIT ?{} OFFSET ?{}",
            where_sql(&clauses),
            params.len() + 1,
            params.len() + 2
        );
        let mut params = params;
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let items = statement
            .query_map(params_from_iter(params), flow_dto_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((items, total))
    }

    fn count_flows(&self, query: &FlowQuery, now: SystemTime) -> Result<usize, ApiError> {
        let (clauses, params) = self.flow_clauses(query, now, "", true);
        let sql = format!("SELECT COUNT(*) FROM flows {}", where_sql(&clauses));
        let total: i64 = self
            .conn
            .query_row(&sql, params_from_iter(params), |row| row.get(0))?;
        Ok(total as usize)
    }

    // -------------------------------------------------------------- endpoints

    pub(crate) fn list_endpoints(
        &self,
        query: &FlowQuery,
    ) -> Result<Page<EndpointSummaryDto>, ApiError> {
        let limit = page_limit(query.limit)?;
        let offset = query.offset.unwrap_or(0);
        let (items, total) = self.endpoint_rows(query, limit, offset)?;
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    pub(crate) fn get_endpoint(&self, address: &str) -> Result<EndpointDetailDto, ApiError> {
        let address: IpAddr = address
            .parse()
            .map_err(|_| ApiError::bad_request(format!("invalid IP address: {address}")))?;
        let address_string = address.to_string();

        let summary_sql = "SELECT remote_scope, remote_country, remote_region, remote_city, \
             remote_asn, remote_org, remote_db_version, remote_enriched_at_ms, \
             SUM(packets), SUM(bytes), COUNT(*), MIN(first_seen_ms), MAX(last_seen_ms) \
             FROM flows WHERE remote_addr = ?1 GROUP BY remote_addr";
        let summary = self
            .conn
            .query_row(summary_sql, [&address_string], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, i64>(12)?,
                ))
            })
            .optional()?
            .ok_or_else(|| {
                ApiError::not_found(format!("no Flow observed for endpoint {address}"))
            })?;

        let scope: AddressScope =
            enum_from_value(&summary.0).unwrap_or_else(|| AddressScope::classify(address));
        let profile = IpProfileDto {
            address: address_string.clone(),
            scope,
            country: summary.1,
            region: summary.2,
            city_approximate: summary.3,
            asn: summary.4,
            organization: summary.5,
            database_version: summary.6,
            enriched_at: summary.7,
        };

        let mut ports_statement = self.conn.prepare(
            "SELECT CASE direction WHEN 'inbound' THEN src_port ELSE dst_port END AS port, \
             protocol, direction, SUM(packets), SUM(bytes), COUNT(*) \
             FROM flows WHERE remote_addr = ?1 GROUP BY port, protocol, direction \
             HAVING port IS NOT NULL ORDER BY 5 DESC",
        )?;
        let ports = ports_statement
            .query_map([&address_string], |row| {
                Ok((
                    row.get::<_, u16>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|(port, protocol, direction, packets, bytes, flow_count)| {
                Some(PortUsageDto {
                    port,
                    protocol: enum_from_value(&protocol)?,
                    direction: enum_from_value(&direction)?,
                    packets: packets as u64,
                    bytes: bytes as u64,
                    flow_count: flow_count as u64,
                })
            })
            .collect();

        let mut domains_statement = self
            .conn
            .prepare("SELECT domains_json FROM flows WHERE remote_addr = ?1")?;
        let mut domains: Vec<DomainRefDto> = Vec::new();
        for row in domains_statement.query_map([&address_string], |row| row.get::<_, String>(0))? {
            let json = row?;
            let parsed: Vec<DomainRefDto> = serde_json::from_str(&json).unwrap_or_default();
            for association in parsed {
                push_domain(&mut domains, &association);
            }
        }
        domains.sort_by(|a, b| a.domain.cmp(&b.domain));

        Ok(EndpointDetailDto {
            address: address_string.clone(),
            profile,
            packets: summary.8 as u64,
            bytes: summary.9 as u64,
            flow_count: summary.10 as u64,
            first_seen: summary.11,
            last_seen: summary.12,
            ports,
            domains,
            flows_url: format!("/v1/flows?ip={}", encode_uri_component(&address_string)),
        })
    }

    fn endpoint_rows(
        &self,
        query: &FlowQuery,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<EndpointSummaryDto>, usize), ApiError> {
        let now = SystemTime::now();
        let (clauses, params) = self.flow_clauses(query, now, "", true);
        let where_clause = where_sql(&clauses);

        let total: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM (SELECT 1 FROM flows {where_clause} GROUP BY remote_addr)"
            ),
            params_from_iter(params.clone()),
            |row| row.get(0),
        )?;

        let order = endpoint_order(query.sort.as_deref())?;
        let sql = format!(
            "SELECT remote_addr, MAX(remote_scope), MAX(remote_country), MAX(remote_region), \
             MAX(remote_asn), MAX(remote_org), SUM(packets) AS total_packets, \
             SUM(bytes) AS total_bytes, COUNT(*), MIN(first_seen_ms), MAX(last_seen_ms) \
             FROM flows {where_clause} GROUP BY remote_addr ORDER BY {order} \
             LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        let mut params = params;
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let items = statement
            .query_map(params_from_iter(params), |row| {
                let scope: String = row.get(1)?;
                Ok(EndpointSummaryDto {
                    address: row.get(0)?,
                    scope: enum_from_value(&scope).unwrap_or(AddressScope::Reserved),
                    country: row.get(2)?,
                    region: row.get(3)?,
                    asn: row.get(4)?,
                    organization: row.get(5)?,
                    packets: row.get::<_, i64>(6)? as u64,
                    bytes: row.get::<_, i64>(7)? as u64,
                    flow_count: row.get::<_, i64>(8)? as u64,
                    first_seen: row.get(9)?,
                    last_seen: row.get(10)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((items, total as usize))
    }

    // ---------------------------------------------------------------- domains

    pub(crate) fn list_domains(
        &self,
        query: &FlowQuery,
    ) -> Result<Page<DomainSummaryDto>, ApiError> {
        let limit = page_limit(query.limit)?;
        let offset = query.offset.unwrap_or(0);
        let (items, total) = self.domain_rows(query, limit, offset)?;
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    pub(crate) fn get_domain(&self, domain: &str) -> Result<DomainDetailDto, ApiError> {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return Err(ApiError::bad_request("domain must not be empty"));
        }
        let query = FlowQuery {
            domain: Some(domain.clone()),
            ..FlowQuery::default()
        };
        let (summaries, _) = self.domain_rows(&query, 1, 0)?;
        let summary = summaries.into_iter().next().ok_or_else(|| {
            ApiError::not_found(format!("no Flow associated with domain {domain}"))
        })?;

        let mut evidence_statement = self.conn.prepare(
            "SELECT je.value->>'evidence', COUNT(*) FROM flows, json_each(flows.domains_json) je \
             WHERE je.value->>'domain' = ?1 GROUP BY 1",
        )?;
        let evidence = evidence_statement
            .query_map([&domain], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|(kind, flows)| {
                Some(EvidenceCountDto {
                    evidence: enum_from_value(&kind)?,
                    flows: flows as u64,
                })
            })
            .collect();

        let quoted = format!("\"{domain}\"");
        let mut addresses_statement = self.conn.prepare(
            "SELECT o.address, MAX(o.confidence), GROUP_CONCAT(DISTINCT o.evidence), \
             MAX(f.remote_country), MAX(f.remote_asn), MAX(f.remote_org), \
             COALESCE(SUM(f.bytes), 0), COALESCE(MAX(f.last_seen_ms), 0) \
             FROM observations o \
             LEFT JOIN flows f ON f.remote_addr = o.address AND instr(f.domains_json, ?2) > 0 \
             WHERE o.domain = ?1 GROUP BY o.address ORDER BY 7 DESC, o.address",
        )?;
        let addresses = addresses_statement
            .query_map(params![domain, quoted], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<u32>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(
                |(address, confidence, evidence, country, asn, organization, bytes, last_seen)| {
                    Some(DomainAddressDto {
                        address,
                        evidence: split_enum_list(&evidence),
                        confidence: enum_from_value(&confidence)?,
                        country,
                        asn,
                        organization,
                        bytes: bytes as u64,
                        last_seen,
                    })
                },
            )
            .collect();

        let mut countries_statement = self.conn.prepare(
            "SELECT f.remote_country, SUM(f.bytes), COUNT(*) \
             FROM flows f, json_each(f.domains_json) je \
             WHERE je.value->>'domain' = ?1 AND f.remote_country IS NOT NULL \
             GROUP BY 1 ORDER BY 2 DESC LIMIT ?2",
        )?;
        let countries = countries_statement
            .query_map(params![domain, TOP_LIST_LIMIT as i64], |row| {
                Ok(CountryCountDto {
                    country: row.get(0)?,
                    bytes: row.get::<_, i64>(1)? as u64,
                    flows: row.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut asns_statement = self.conn.prepare(
            "SELECT f.remote_asn, MAX(f.remote_org), SUM(f.bytes), COUNT(*) \
             FROM flows f, json_each(f.domains_json) je \
             WHERE je.value->>'domain' = ?1 AND f.remote_asn IS NOT NULL \
             GROUP BY 1 ORDER BY 3 DESC LIMIT ?2",
        )?;
        let asns = asns_statement
            .query_map(params![domain, TOP_LIST_LIMIT as i64], |row| {
                Ok(AsnCountDto {
                    asn: row.get(0)?,
                    organization: row.get(1)?,
                    bytes: row.get::<_, i64>(2)? as u64,
                    flows: row.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(DomainDetailDto {
            domain: domain.clone(),
            packets: summary.packets,
            bytes: summary.bytes,
            flow_count: summary.flow_count,
            first_seen: summary.first_seen,
            last_seen: summary.last_seen,
            evidence,
            addresses,
            countries,
            asns,
            flows_url: format!("/v1/flows?domain={}", encode_uri_component(&domain)),
        })
    }

    fn domain_rows(
        &self,
        query: &FlowQuery,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<DomainSummaryDto>, usize), ApiError> {
        let now = SystemTime::now();
        let (mut clauses, mut params) = self.flow_clauses(query, now, "flows.", false);
        clauses.push("je.value->>'domain' IS NOT NULL".to_owned());
        if let Some(domain) = query.domain.as_deref().map(normalize_domain) {
            clauses.push("je.value->>'domain' = ?".to_owned());
            params.push(Value::Text(domain));
        }
        if let Some(evidence) = query.evidence {
            clauses.push("je.value->>'evidence' = ?".to_owned());
            params.push(Value::Text(enum_value(evidence)));
        }
        if let Some(confidence) = query.confidence {
            clauses.push("je.value->>'confidence' = ?".to_owned());
            params.push(Value::Text(enum_value(confidence)));
        }
        let where_clause = where_sql(&clauses);

        let total: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(DISTINCT je.value->>'domain') \
                 FROM flows, json_each(flows.domains_json) je {where_clause}"
            ),
            params_from_iter(params.clone()),
            |row| row.get(0),
        )?;

        let order = domain_order(query.sort.as_deref())?;
        let sql = format!(
            "SELECT je.value->>'domain' AS domain, SUM(flows.packets) AS total_packets, \
             SUM(flows.bytes) AS total_bytes, COUNT(*) AS flow_count, \
             MIN(flows.first_seen_ms), MAX(flows.last_seen_ms), \
             GROUP_CONCAT(DISTINCT je.value->>'evidence') AS evidences \
             FROM flows, json_each(flows.domains_json) je {where_clause} GROUP BY 1 \
             ORDER BY {order} LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let items = statement
            .query_map(params_from_iter(params), |row| {
                Ok(DomainSummaryDto {
                    domain: row.get(0)?,
                    packets: row.get::<_, i64>(1)? as u64,
                    bytes: row.get::<_, i64>(2)? as u64,
                    flow_count: row.get::<_, i64>(3)? as u64,
                    first_seen: row.get(4)?,
                    last_seen: row.get(5)?,
                    evidence: split_enum_list(&row.get::<_, String>(6)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((items, total as usize))
    }

    // --------------------------------------------------------------- overview

    pub(crate) fn overview(
        &self,
        range: TimeRange,
        now: SystemTime,
    ) -> Result<OverviewDto, ApiError> {
        let query = FlowQuery {
            range: Some(range),
            limit: Some(TOP_LIST_LIMIT),
            ..FlowQuery::default()
        };
        let (clauses, params) = self.flow_clauses(&query, now, "", true);
        let where_clause = where_sql(&clauses);

        let mut totals = DirectionTotalsDto::default();
        {
            let mut statement = self.conn.prepare(&format!(
                "SELECT direction, SUM(packets), SUM(bytes) FROM flows {where_clause} \
                 GROUP BY direction"
            ))?;
            for row in statement.query_map(params_from_iter(params.clone()), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })? {
                let (direction, packets, bytes) = row?;
                let counters = CountersDto {
                    packets: packets as u64,
                    bytes: bytes as u64,
                };
                match direction.as_str() {
                    "inbound" => totals.inbound = counters,
                    "outbound" => totals.outbound = counters,
                    _ => {}
                }
            }
        }

        let (flows_total, flows_with_domain, active_flows): (i64, i64, i64) = self.conn.query_row(
            &format!(
                "SELECT COUNT(*), COALESCE(SUM(domains_json <> '[]'), 0), \
                     COALESCE(SUM(state = 'active'), 0) FROM flows {where_clause}"
            ),
            params_from_iter(params),
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let ratio = if flows_total == 0 {
            0.0
        } else {
            flows_with_domain as f64 / flows_total as f64
        };

        let top_countries = self.aggregate_countries(&query, now)?;
        let top_asns = self.aggregate_asns(&query, now)?;

        Ok(OverviewDto {
            range: range.as_str(),
            generated_at: unix_millis(now),
            rates: if self.rates_are_fresh(now) {
                RateDto {
                    inbound_bps: self.rates.inbound_bps,
                    outbound_bps: self.rates.outbound_bps,
                }
            } else {
                RateDto::default()
            },
            totals,
            timeline: self.timeline(range, now)?,
            top_endpoints: self.endpoint_rows(&query, TOP_LIST_LIMIT, 0)?.0,
            top_domains: self.domain_rows(&query, TOP_LIST_LIMIT, 0)?.0,
            top_countries,
            top_asns,
            active_flows: active_flows as u64,
            domain_visibility: DomainVisibilityDto {
                flows_with_domain: flows_with_domain as u64,
                flows_total: flows_total as u64,
                ratio,
            },
            health: self.health.as_ref().map(CollectorHealthDto::from_health),
        })
    }

    fn aggregate_countries(
        &self,
        query: &FlowQuery,
        now: SystemTime,
    ) -> Result<Vec<CountryCountDto>, ApiError> {
        let (mut clauses, params) = self.flow_clauses(query, now, "", true);
        clauses.push("remote_country IS NOT NULL".to_owned());
        let sql = format!(
            "SELECT remote_country, SUM(bytes), COUNT(*) FROM flows {} \
             GROUP BY remote_country ORDER BY 2 DESC LIMIT {TOP_LIST_LIMIT}",
            where_sql(&clauses)
        );
        let mut statement = self.conn.prepare(&sql)?;
        let items = statement
            .query_map(params_from_iter(params), |row| {
                Ok(CountryCountDto {
                    country: row.get(0)?,
                    bytes: row.get::<_, i64>(1)? as u64,
                    flows: row.get::<_, i64>(2)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    fn aggregate_asns(
        &self,
        query: &FlowQuery,
        now: SystemTime,
    ) -> Result<Vec<AsnCountDto>, ApiError> {
        let (mut clauses, params) = self.flow_clauses(query, now, "", true);
        clauses.push("remote_asn IS NOT NULL".to_owned());
        let sql = format!(
            "SELECT remote_asn, MAX(remote_org), SUM(bytes), COUNT(*) FROM flows {} \
             GROUP BY remote_asn ORDER BY 3 DESC LIMIT {TOP_LIST_LIMIT}",
            where_sql(&clauses)
        );
        let mut statement = self.conn.prepare(&sql)?;
        let items = statement
            .query_map(params_from_iter(params), |row| {
                Ok(AsnCountDto {
                    asn: row.get(0)?,
                    organization: row.get(1)?,
                    bytes: row.get::<_, i64>(2)? as u64,
                    flows: row.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    fn timeline(&self, range: TimeRange, now: SystemTime) -> Result<TimelineDto, ApiError> {
        let (resolution, step_ms) = match range {
            TimeRange::Minute15 | TimeRange::Hour1 => ("minute", 60_000i64),
            TimeRange::Hour24 | TimeRange::Day7 => ("hour", 3_600_000i64),
        };
        let end = unix_millis(now).div_euclid(step_ms) * step_ms;
        let start = unix_millis(range.cutoff(now)).div_euclid(step_ms) * step_ms;

        let mut points: HashMap<i64, TimelinePointDto> = HashMap::new();
        let mut statement = self.conn.prepare(
            "SELECT start_ms, in_packets, in_bytes, out_packets, out_bytes \
             FROM traffic_buckets WHERE resolution = ?1 AND start_ms BETWEEN ?2 AND ?3 \
             ORDER BY start_ms",
        )?;
        for row in statement.query_map(params![resolution, start, end], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })? {
            let (at, in_packets, in_bytes, out_packets, out_bytes) = row?;
            points.insert(
                at,
                TimelinePointDto {
                    start: at,
                    inbound: CountersDto {
                        packets: in_packets as u64,
                        bytes: in_bytes as u64,
                    },
                    outbound: CountersDto {
                        packets: out_packets as u64,
                        bytes: out_bytes as u64,
                    },
                },
            );
        }

        let mut ordered = Vec::new();
        let mut at = start;
        while at <= end {
            ordered.push(points.remove(&at).unwrap_or(TimelinePointDto {
                start: at,
                ..TimelinePointDto::default()
            }));
            at += step_ms;
        }

        Ok(TimelineDto {
            resolution,
            points: ordered,
        })
    }

    // ---------------------------------------------------------------- exports

    pub(crate) fn create_export(
        &mut self,
        request: &CreateExportRequest,
    ) -> Result<ExportTaskDto, ApiError> {
        let now = SystemTime::now();
        let (flows, total) = self.flows_page(&request.query, EXPORT_MAX_RECORDS, 0)?;
        let truncated = total > flows.len();

        let (content, content_type, record_count) = match request.format {
            ExportFormat::Json => {
                let domains = self.domain_rows(&request.query, EXPORT_MAX_RECORDS, 0)?.0;
                let profiles = self.export_profiles(&request.query, now)?;
                let document = ExportDocument {
                    generated_at: unix_millis(now),
                    range: request.query.range.map(TimeRange::as_str),
                    truncated,
                    flows,
                    domains,
                    profiles,
                    health: self.health.as_ref().map(CollectorHealthDto::from_health),
                };
                let bytes = serde_json::to_vec_pretty(&document)
                    .map_err(|error| ApiError::internal(format!("serialize export: {error}")))?;
                (
                    bytes,
                    ExportFormat::Json.content_type(),
                    document.flows.len(),
                )
            }
            ExportFormat::Csv => {
                let csv = export_csv(&flows);
                (
                    csv.into_bytes(),
                    ExportFormat::Csv.content_type(),
                    flows.len(),
                )
            }
        };

        self.export_counter += 1;
        let id = format!("exp-{}", self.export_counter);
        let expires_at = now.checked_add(self.export_ttl).unwrap_or(now);
        self.conn.execute(
            "INSERT INTO exports (id, format, range, created_at_ms, expires_at_ms, \
             record_count, truncated, content_type, content) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id,
                enum_value(request.format),
                request.query.range.map(TimeRange::as_str),
                unix_millis(now),
                unix_millis(expires_at),
                record_count as i64,
                truncated as i64,
                content_type,
                content,
            ],
        )?;
        self.audit("export.create", "completed");
        self.export_by_id(&id)?
            .ok_or_else(|| ApiError::internal("export insert was not visible"))
    }

    pub(crate) fn list_exports(&self) -> Result<Vec<ExportTaskDto>, ApiError> {
        let mut statement = self.conn.prepare(
            "SELECT id, format, range, created_at_ms, expires_at_ms, record_count, \
             truncated, content_type, length(content) FROM exports \
             ORDER BY created_at_ms DESC",
        )?;
        let items = statement
            .query_map([], export_task_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(items)
    }

    pub(crate) fn get_export(&self, id: &str) -> Result<ExportTaskDto, ApiError> {
        self.export_by_id(id)?
            .ok_or_else(|| ApiError::not_found(format!("no export with id {id}")))
    }

    pub(crate) fn export_content(&self, id: &str) -> Result<ExportContent, ApiError> {
        let row = self
            .conn
            .query_row(
                "SELECT content_type, content, expires_at_ms, format FROM exports WHERE id = ?1",
                [id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| ApiError::not_found(format!("no export with id {id}")))?;
        if unix_millis(SystemTime::now()) >= row.2 {
            return Err(ApiError::gone(format!(
                "export {id} content has expired and was discarded"
            )));
        }
        let format: ExportFormat = enum_from_value(&row.3).unwrap_or_default();
        Ok(ExportContent {
            content_type: row.0,
            file_name: format!("zimascope-export-{id}.{}", format.extension()),
            bytes: row.1,
        })
    }

    pub(crate) fn delete_export(&mut self, id: &str) -> Result<(), ApiError> {
        let removed = self
            .conn
            .execute("DELETE FROM exports WHERE id = ?1", [id])?;
        if removed == 0 {
            return Err(ApiError::not_found(format!("no export with id {id}")));
        }
        self.audit("export.delete", "completed");
        Ok(())
    }

    fn export_by_id(&self, id: &str) -> Result<Option<ExportTaskDto>, ApiError> {
        self.conn
            .query_row(
                "SELECT id, format, range, created_at_ms, expires_at_ms, record_count, \
                 truncated, content_type, length(content) FROM exports WHERE id = ?1",
                [id],
                export_task_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    fn export_profiles(
        &self,
        query: &FlowQuery,
        now: SystemTime,
    ) -> Result<Vec<IpProfileDto>, ApiError> {
        let (clauses, mut params) = self.flow_clauses(query, now, "", true);
        let sql = format!(
            "SELECT DISTINCT remote_addr, remote_scope, remote_country, remote_region, \
             remote_city, remote_asn, remote_org, remote_db_version, remote_enriched_at_ms \
             FROM flows {} LIMIT ?{}",
            where_sql(&clauses),
            params.len() + 1
        );
        params.push(Value::Integer(EXPORT_MAX_RECORDS as i64));
        let mut statement = self.conn.prepare(&sql)?;
        let profiles = statement
            .query_map(params_from_iter(params), |row| {
                let scope: String = row.get(1)?;
                Ok(IpProfileDto {
                    address: row.get(0)?,
                    scope: enum_from_value(&scope).unwrap_or(AddressScope::Reserved),
                    country: row.get(2)?,
                    region: row.get(3)?,
                    city_approximate: row.get(4)?,
                    asn: row.get(5)?,
                    organization: row.get(6)?,
                    database_version: row.get(7)?,
                    enriched_at: row.get(8)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(profiles)
    }

    // -------------------------------------------------------------- lifecycle

    pub(crate) fn clear_history(&mut self) {
        let result = (|| -> Result<(), ApiError> {
            self.conn.execute_batch(
                "DELETE FROM flows; DELETE FROM observations; DELETE FROM traffic_buckets; \
                 DELETE FROM exports;",
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            self.database_error = Some(error.to_string());
        }
        self.rates = Rates::default();
        self.audit("history.clear", "completed");
    }

    pub(crate) fn load_settings(&self) -> Result<Option<(Settings, u64)>, ApiError> {
        let row = self
            .conn
            .query_row(
                "SELECT json, version FROM settings WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        Ok(row.and_then(|(json, version)| {
            serde_json::from_str::<Settings>(&json)
                .ok()
                .map(|settings| (settings, version as u64))
        }))
    }

    pub(crate) fn save_settings(
        &mut self,
        settings: &Settings,
        version: u64,
    ) -> Result<(), ApiError> {
        let json = serde_json::to_string(settings)
            .map_err(|error| ApiError::internal(format!("serialize settings: {error}")))?;
        self.conn.execute(
            "INSERT INTO settings (id, json, version) VALUES (1, ?1, ?2) \
             ON CONFLICT(id) DO UPDATE SET json = excluded.json, version = excluded.version",
            params![json, version as i64],
        )?;
        self.enforce_policy(settings, SystemTime::now())
    }

    pub(crate) fn health(&self) -> Option<&CollectorHealth> {
        self.health.as_ref()
    }

    pub(crate) fn last_batch_at(&self) -> Option<SystemTime> {
        self.last_batch_at
    }

    pub(crate) fn batch_sequence(&self) -> u64 {
        self.batch_sequence
    }

    pub(crate) fn database_error(&self) -> Option<&str> {
        self.database_error.as_deref()
    }

    pub(crate) fn set_database_error(&mut self, error: String) {
        self.database_error = Some(error);
    }

    pub(crate) fn audit_entries(
        &self,
    ) -> impl Iterator<Item = (&'static str, &'static str, SystemTime)> + '_ {
        self.audit
            .iter()
            .map(|entry| (entry.action, entry.outcome, entry.at))
    }

    pub(crate) fn enrichment_status(&self) -> (EnrichmentStats, Option<String>) {
        (self.enricher.stats(), self.enrichment_error.clone())
    }

    #[cfg(test)]
    pub(crate) fn set_geoip_database(&mut self, database: GeoIpDatabase) {
        self.enricher.set_database(database);
        self.enrichment_error = None;
    }

    fn audit(&mut self, action: &'static str, outcome: &'static str) {
        if self.audit.len() >= AUDIT_CAPACITY {
            self.audit.pop_front();
        }
        self.audit.push_back(AuditEntry {
            at: SystemTime::now(),
            action,
            outcome,
        });
    }

    fn rates_are_fresh(&self, now: SystemTime) -> bool {
        let ttl = self
            .last_interval
            .saturating_mul(3)
            .max(Duration::from_secs(5));
        self.last_batch_at
            .and_then(|at| now.duration_since(at).ok())
            .is_some_and(|age| age <= ttl)
    }

    /// SQL predicates shared by flows, endpoints and domains.
    ///
    /// `prefix` qualifies Flow columns when the query joins `json_each`.
    /// `association_filters` is disabled by domain queries, which evaluate
    /// `domain`, `evidence` and `confidence` on the joined association.
    fn flow_clauses(
        &self,
        query: &FlowQuery,
        now: SystemTime,
        prefix: &str,
        association_filters: bool,
    ) -> (Vec<String>, Vec<Value>) {
        let mut clauses = Vec::new();
        let mut params = Vec::new();

        if let Some(q) = query
            .q
            .as_deref()
            .map(|q| q.trim().to_ascii_lowercase())
            .filter(|q| !q.is_empty())
        {
            clauses.push(format!(
                "instr(lower(hex({prefix}id) || ' ' || {prefix}direction || ' ' || \
                 {prefix}protocol || ' ' || {prefix}state || ' ' || \
                 coalesce({prefix}end_reason, '') || ' ' || {prefix}src_addr || ' ' || \
                 coalesce({prefix}src_port, '') || ' ' || {prefix}dst_addr || ' ' || \
                 coalesce({prefix}dst_port, '') || ' ' || coalesce({prefix}interface, '') || \
                 ' ' || {prefix}domains_json), ?) > 0"
            ));
            params.push(Value::Text(q));
        }
        if let Some(range) = query.range {
            clauses.push(format!("{prefix}last_seen_ms >= ?"));
            params.push(Value::Integer(unix_millis(range.cutoff(now))));
        }
        if let Some(direction) = query.direction {
            clauses.push(format!("{prefix}direction = ?"));
            params.push(Value::Text(enum_value(direction)));
        }
        if let Some(protocol) = query.protocol {
            clauses.push(format!("{prefix}protocol = ?"));
            params.push(Value::Text(enum_value(protocol)));
        }
        if let Some(ip) = query.ip {
            clauses.push(format!("({prefix}src_addr = ? OR {prefix}dst_addr = ?)"));
            params.push(Value::Text(ip.to_string()));
            params.push(Value::Text(ip.to_string()));
        }
        if let Some(src_ip) = query.src_ip {
            clauses.push(format!("{prefix}src_addr = ?"));
            params.push(Value::Text(src_ip.to_string()));
        }
        if let Some(dst_ip) = query.dst_ip {
            clauses.push(format!("{prefix}dst_addr = ?"));
            params.push(Value::Text(dst_ip.to_string()));
        }
        if let Some(port) = query.port {
            clauses.push(format!("({prefix}src_port = ? OR {prefix}dst_port = ?)"));
            params.push(Value::Integer(port as i64));
            params.push(Value::Integer(port as i64));
        }
        if association_filters {
            if let Some(domain) = query.domain.as_deref().map(normalize_domain) {
                clauses.push(format!("instr({prefix}domains_json, ?) > 0"));
                params.push(Value::Text(format!("\"{domain}\"")));
            }
            if let Some(evidence) = query.evidence {
                clauses.push(format!("instr({prefix}domains_json, ?) > 0"));
                params.push(Value::Text(format!(
                    "\"evidence\":\"{}\"",
                    enum_value(evidence)
                )));
            }
            if let Some(confidence) = query.confidence {
                clauses.push(format!("instr({prefix}domains_json, ?) > 0"));
                params.push(Value::Text(format!(
                    "\"confidence\":\"{}\"",
                    enum_value(confidence)
                )));
            }
        }
        if let Some(country) = &query.country {
            clauses.push(format!("{prefix}remote_country = ? COLLATE NOCASE"));
            params.push(Value::Text(country.clone()));
        }
        if let Some(asn) = query.asn {
            clauses.push(format!("{prefix}remote_asn = ?"));
            params.push(Value::Integer(asn as i64));
        }
        if let Some(organization) = &query.organization {
            clauses.push(format!(
                "instr(lower(coalesce({prefix}remote_org, '')), ?) > 0"
            ));
            params.push(Value::Text(organization.to_ascii_lowercase()));
        }
        if let Some(scope) = query.scope {
            clauses.push(format!("{prefix}remote_scope = ?"));
            params.push(Value::Text(enum_value(scope)));
        }
        if let Some(state) = query.state {
            clauses.push(format!("{prefix}state = ?"));
            params.push(Value::Text(state.as_str().to_owned()));
        }
        if let Some(has_domain) = query.has_domain {
            clauses.push(format!("({prefix}domains_json <> '[]') = ?"));
            params.push(Value::Integer(i64::from(has_domain)));
        }

        (clauses, params)
    }
}

#[derive(serde::Serialize)]
struct ExportDocument {
    generated_at: i64,
    range: Option<&'static str>,
    truncated: bool,
    flows: Vec<FlowDto>,
    domains: Vec<DomainSummaryDto>,
    profiles: Vec<IpProfileDto>,
    health: Option<CollectorHealthDto>,
}

// ------------------------------------------------------------------ helpers

fn store_observation(
    tx: &rusqlite::Transaction<'_>,
    observation: &DomainObservation,
    now_instant: Instant,
    now_system: SystemTime,
) -> Result<bool, ApiError> {
    let observed_at = instant_to_system(observation.observed_at, now_instant, now_system);
    let expires_at = instant_to_system(observation.expires_at, now_instant, now_system);
    if expires_at <= now_system {
        return Ok(false);
    }
    let domain = normalize_domain(&observation.domain);
    if domain.is_empty() {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO observations (domain, address, evidence, confidence, last_observed_ms, \
         expires_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(domain, address, evidence) DO UPDATE SET \
         last_observed_ms = MAX(observations.last_observed_ms, excluded.last_observed_ms), \
         expires_at_ms = MAX(observations.expires_at_ms, excluded.expires_at_ms), \
         confidence = excluded.confidence",
        params![
            domain,
            observation.address.to_string(),
            enum_value(observation.evidence),
            enum_value(observation.confidence),
            unix_millis(observed_at),
            unix_millis(expires_at),
        ],
    )?;
    Ok(true)
}

fn associate_address(
    tx: &rusqlite::Transaction<'_>,
    address: IpAddr,
    now: SystemTime,
) -> Result<String, ApiError> {
    let mut statement = tx.prepare(
        "SELECT domain, evidence, confidence, last_observed_ms FROM observations \
         WHERE address = ?1 AND expires_at_ms > ?2",
    )?;
    let mut candidates = statement
        .query_map(params![address.to_string(), unix_millis(now)], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .into_iter()
        .filter_map(|(domain, evidence, confidence, last_observed)| {
            Some((
                domain,
                enum_from_value::<DomainEvidence>(&evidence)?,
                enum_from_value::<AssociationConfidence>(&confidence)?,
                last_observed,
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        evidence_rank(b.1)
            .cmp(&evidence_rank(a.1))
            .then(b.3.cmp(&a.3))
            .then(a.0.cmp(&b.0))
    });

    let mut domains: Vec<DomainRefDto> = Vec::new();
    for (domain, evidence, confidence, _) in candidates {
        if domains.iter().any(|known| known.domain == domain) {
            continue;
        }
        domains.push(DomainRefDto {
            domain,
            evidence,
            confidence,
        });
        if domains.len() >= MAX_DOMAIN_CANDIDATES {
            break;
        }
    }
    serde_json::to_string(&domains)
        .map_err(|error| ApiError::internal(format!("serialize domains: {error}")))
}

fn upsert_flow(
    tx: &rusqlite::Transaction<'_>,
    id: u64,
    update: &FlowUpdate,
    now_instant: Instant,
    now_system: SystemTime,
    enricher: &mut Enricher,
    interfaces: &HashMap<u32, Box<str>>,
) -> Result<(), ApiError> {
    let remote = remote_endpoint(&update.key);
    let profile = enricher.profile(remote.address);
    let domains_json = associate_address(tx, remote.address, now_system)?;
    let first_seen = instant_to_system(update.first_seen, now_instant, now_system);
    let last_seen = instant_to_system(update.last_seen, now_instant, now_system);
    let end_reason = match update.state {
        FlowState::Ended(reason) => Some(enum_value(reason)),
        FlowState::Active => None,
    };
    let interface = interfaces.get(&update.key.interface_index.get());

    tx.execute(
        "INSERT INTO flows (id, direction, protocol, src_addr, src_port, dst_addr, dst_port, \
         ifindex, interface, packets, bytes, first_seen_ms, last_seen_ms, state, end_reason, \
         remote_addr, remote_port, remote_scope, remote_country, remote_region, remote_city, \
         remote_asn, remote_org, remote_db_version, remote_enriched_at_ms, domains_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
         ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26) \
         ON CONFLICT(id) DO UPDATE SET \
         packets = excluded.packets, bytes = excluded.bytes, \
         first_seen_ms = MIN(flows.first_seen_ms, excluded.first_seen_ms), \
         last_seen_ms = MAX(flows.last_seen_ms, excluded.last_seen_ms), \
         state = excluded.state, end_reason = excluded.end_reason, \
         interface = excluded.interface, domains_json = excluded.domains_json, \
         remote_scope = excluded.remote_scope, remote_country = excluded.remote_country, \
         remote_region = excluded.remote_region, remote_city = excluded.remote_city, \
         remote_asn = excluded.remote_asn, remote_org = excluded.remote_org, \
         remote_db_version = excluded.remote_db_version, \
         remote_enriched_at_ms = excluded.remote_enriched_at_ms",
        params![
            id as i64,
            enum_value(update.key.direction),
            enum_value(update.key.protocol),
            update.key.source.address.to_string(),
            update.key.source.port.map(i64::from),
            update.key.destination.address.to_string(),
            update.key.destination.port.map(i64::from),
            update.key.interface_index.get(),
            interface.map(Box::as_ref),
            update.total.packets as i64,
            update.total.bytes as i64,
            unix_millis(first_seen),
            unix_millis(last_seen),
            flow_state_name(update.state),
            end_reason,
            remote.address.to_string(),
            remote.port.map(i64::from),
            enum_value(profile.scope),
            profile.country.as_ref().map(Box::as_ref),
            profile.region.as_ref().map(Box::as_ref),
            profile.city_approximate.as_ref().map(Box::as_ref),
            profile.asn.map(i64::from),
            profile.organization.as_ref().map(Box::as_ref),
            profile.database_version.as_ref().map(Box::as_ref),
            unix_millis(profile.enriched_at),
            domains_json,
        ],
    )?;
    Ok(())
}

fn add_bucket(
    tx: &rusqlite::Transaction<'_>,
    resolution: &str,
    start: SystemTime,
    inbound: TrafficCounters,
    outbound: TrafficCounters,
) -> Result<(), ApiError> {
    tx.execute(
        "INSERT INTO traffic_buckets (resolution, start_ms, in_packets, in_bytes, out_packets, \
         out_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(resolution, start_ms) DO UPDATE SET \
         in_packets = traffic_buckets.in_packets + excluded.in_packets, \
         in_bytes = traffic_buckets.in_bytes + excluded.in_bytes, \
         out_packets = traffic_buckets.out_packets + excluded.out_packets, \
         out_bytes = traffic_buckets.out_bytes + excluded.out_bytes",
        params![
            resolution,
            unix_millis(start),
            inbound.packets as i64,
            inbound.bytes as i64,
            outbound.packets as i64,
            outbound.bytes as i64,
        ],
    )?;
    Ok(())
}

fn flow_dto_from_row(row: &Row<'_>) -> rusqlite::Result<FlowDto> {
    let direction: String = row.get(1)?;
    let protocol: String = row.get(2)?;
    let state: String = row.get(13)?;
    let end_reason: Option<String> = row.get(14)?;
    let scope: String = row.get(17)?;
    let domains_json: String = row.get(25)?;
    let first_seen: i64 = row.get(11)?;
    let last_seen: i64 = row.get(12)?;

    Ok(FlowDto {
        id: format!("{:016x}", row.get::<_, i64>(0)? as u64),
        direction: enum_from_value(&direction).ok_or_else(|| invalid_enum("direction"))?,
        protocol: enum_from_value(&protocol).ok_or_else(|| invalid_enum("protocol"))?,
        state: if state == "active" { "active" } else { "ended" },
        end_reason: end_reason.as_deref().and_then(enum_from_value),
        source: EndpointDto {
            address: row.get(3)?,
            port: row.get::<_, Option<i64>>(4)?.map(|port| port as u16),
        },
        destination: EndpointDto {
            address: row.get(5)?,
            port: row.get::<_, Option<i64>>(6)?.map(|port| port as u16),
        },
        remote: EndpointDto {
            address: row.get(15)?,
            port: row.get::<_, Option<i64>>(16)?.map(|port| port as u16),
        },
        remote_profile: IpProfileDto {
            address: row.get(15)?,
            scope: enum_from_value(&scope).unwrap_or(AddressScope::Reserved),
            country: row.get(18)?,
            region: row.get(19)?,
            city_approximate: row.get(20)?,
            asn: row.get(21)?,
            organization: row.get(22)?,
            database_version: row.get(23)?,
            enriched_at: row.get(24)?,
        },
        interface: row.get(8)?,
        packets: row.get::<_, i64>(9)? as u64,
        bytes: row.get::<_, i64>(10)? as u64,
        first_seen,
        last_seen,
        duration_ms: (last_seen - first_seen).max(0) as u64,
        domains: serde_json::from_str(&domains_json).unwrap_or_default(),
    })
}

fn export_task_from_row(row: &Row<'_>) -> rusqlite::Result<ExportTaskDto> {
    let format: String = row.get(1)?;
    let expires_at: i64 = row.get(4)?;
    let status = if unix_millis(SystemTime::now()) >= expires_at {
        "expired"
    } else {
        "completed"
    };
    let id: String = row.get(0)?;
    Ok(ExportTaskDto {
        download_url: format!("/v1/exports/{id}/content"),
        id,
        status,
        format: enum_from_value(&format).unwrap_or_default(),
        range: row.get(2)?,
        created_at: row.get(3)?,
        expires_at,
        record_count: row.get::<_, i64>(5)? as u64,
        size_bytes: row.get::<_, i64>(8)? as u64,
        truncated: row.get::<_, i64>(6)? != 0,
        content_type: row.get(7)?,
    })
}

fn export_csv(flows: &[FlowDto]) -> String {
    use std::fmt::Write as _;

    let mut csv = String::from(
        "id,direction,protocol,state,end_reason,src_ip,src_port,dst_ip,dst_port,remote_ip,\
         remote_port,interface,packets,bytes,first_seen_ms,last_seen_ms,domain,evidence,confidence\n",
    );
    for flow in flows {
        let (domain, evidence, confidence) = flow
            .domains
            .first()
            .map(|association| {
                (
                    association.domain.as_str(),
                    enum_value(association.evidence),
                    enum_value(association.confidence),
                )
            })
            .unwrap_or_default();
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            flow.id,
            enum_value(flow.direction),
            enum_value(flow.protocol),
            flow.state,
            flow.end_reason.map(enum_value).unwrap_or_default(),
            flow.source.address,
            optional_port(flow.source.port),
            flow.destination.address,
            optional_port(flow.destination.port),
            flow.remote.address,
            optional_port(flow.remote.port),
            csv_field(flow.interface.as_deref().unwrap_or("")),
            flow.packets,
            flow.bytes,
            flow.first_seen,
            flow.last_seen,
            csv_field(domain),
            evidence,
            confidence,
        );
    }
    csv
}

fn page_limit(limit: Option<usize>) -> Result<usize, ApiError> {
    use super::dto::{DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT};
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 || limit > MAX_PAGE_LIMIT {
        return Err(ApiError::bad_request(format!(
            "limit must be between 1 and {MAX_PAGE_LIMIT}"
        )));
    }
    Ok(limit)
}

fn split_sort<'a>(sort: Option<&'a str>, default: &'static str) -> (&'a str, bool) {
    let raw = sort.unwrap_or(default);
    match raw.strip_prefix('-') {
        Some(field) => (field, true),
        None => (raw.strip_prefix('+').unwrap_or(raw), false),
    }
}

fn flow_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-last_seen");
    let column = match field {
        "last_seen" => "last_seen_ms",
        "first_seen" => "first_seen_ms",
        "bytes" => "bytes",
        "packets" => "packets",
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, id {direction}"))
}

fn endpoint_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-bytes");
    let column = match field {
        "bytes" => "total_bytes",
        "packets" => "total_packets",
        "last_seen" => "last_seen_ms",
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, remote_addr {direction}"))
}

fn domain_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-bytes");
    let column = match field {
        "bytes" => "total_bytes",
        "packets" => "total_packets",
        "last_seen" => "last_seen_ms",
        "domain" => "domain",
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, domain {direction}"))
}

fn unsupported_sort(field: &str) -> ApiError {
    ApiError::bad_request(format!("unsupported sort field: {field:?}"))
}

fn where_sql(clauses: &[String]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    }
}

fn split_enum_list(value: &str) -> Vec<DomainEvidence> {
    value
        .split(',')
        .filter_map(|kind| enum_from_value(kind.trim()))
        .collect()
}

fn push_domain(domains: &mut Vec<DomainRefDto>, association: &DomainRefDto) {
    if let Some(existing) = domains
        .iter_mut()
        .find(|existing| existing.domain == association.domain)
    {
        if evidence_rank(association.evidence) > evidence_rank(existing.evidence) {
            existing.evidence = association.evidence;
        }
        if association.confidence == AssociationConfidence::Direct {
            existing.confidence = AssociationConfidence::Direct;
        }
    } else {
        domains.push(association.clone());
    }
}

fn evidence_rank(evidence: DomainEvidence) -> u8 {
    match evidence {
        DomainEvidence::TlsSni | DomainEvidence::HttpHost => 2,
        DomainEvidence::Dns => 1,
    }
}

fn invalid_enum(field: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Text,
        format!("unknown {field} value in storage").into(),
    )
}

fn remote_endpoint(key: &FlowKey) -> &Endpoint {
    match key.direction {
        FlowDirection::Inbound => &key.source,
        FlowDirection::Outbound => &key.destination,
    }
}

fn flow_id(key: &FlowKey) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

fn add_counters(target: &mut TrafficCounters, delta: TrafficCounters) {
    target.packets = target.packets.saturating_add(delta.packets);
    target.bytes = target.bytes.saturating_add(delta.bytes);
}

fn truncate_time(time: SystemTime, step_secs: u64) -> SystemTime {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds / step_secs * step_secs)
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn instant_to_system(instant: Instant, now_instant: Instant, now_system: SystemTime) -> SystemTime {
    if instant >= now_instant {
        now_system
            .checked_add(instant - now_instant)
            .unwrap_or(now_system)
    } else {
        now_system
            .checked_sub(now_instant - instant)
            .unwrap_or(now_system)
    }
}

fn optional_port(port: Option<u16>) -> String {
    port.map(|port| port.to_string()).unwrap_or_default()
}

fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn encode_uri_component(value: &str) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(byte as char);
            }
            _ => {
                let _ = write!(output, "%{byte:02X}");
            }
        }
    }
    output
}
