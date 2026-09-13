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
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use hashbrown::{HashMap, HashSet};
use rusqlite::{
    Connection, OptionalExtension, Row, functions::FunctionFlags, params, params_from_iter,
    types::Value,
};
use zimascope_common::{
    kernel_abi::RuleAction,
    model::{
        AddressScope, AssociationConfidence, CollectionBatch, CollectorHealth, DomainEvidence,
        DomainObservation, Endpoint, FlowDirection, FlowKey, FlowState, FlowUpdate, Protocol,
        TrafficCounters,
    },
};

#[cfg(test)]
use crate::enrichment::GeoIpDatabase;
use crate::enrichment::{DEFAULT_CACHE_CAPACITY, Enricher, EnrichmentStats};
use crate::policy::{ActionSpec, RuleDirection, TrafficRule, action_from_name, action_name};
use crate::query::{ApplicationComms, Selector};

use crate::SharedFingerprints;
use crate::proxy::{ProxyKey, ProxyResolver};

use super::application::{ApplicationResolver, ResolvedApplication};
use super::dto::{
    ApplicationDestinationDto, ApplicationDetailDto, ApplicationRefDto, ApplicationSummaryDto,
    AsnCountDto, CollectorHealthDto, ConnectionDto, CountersDto, CountryCountDto,
    CreateExportRequest, DirectionTotalsDto, DomainAddressDto, DomainDetailDto,
    DomainObservationDto, DomainRefDto, DomainSummaryDto, DomainVisibilityDto, EndpointDetailDto,
    EndpointDto, EndpointSummaryDto, EvidenceCountDto, ExportFormat, ExportTaskDto, FlowDto,
    FlowQuery, FlowStateParam, IpProfileDto, OverviewDto, Page, PortUsageDto, ProxiedTrafficDto,
    RateDto, TickDto, TickOverviewDto, TickTrafficDto, TimeRange, TimelineDto, TimelinePointDto,
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
/// Peer addresses embedded in one Application detail response.
const MAX_APPLICATION_DESTINATIONS: usize = 12;

/// How often retention and capacity enforcement runs. The flow table is
/// capped; a few seconds of slack is invisible, the full-table scans are not.
const POLICY_INTERVAL: Duration = Duration::from_secs(5);

/// How long the whole-history overview counters are reused.
const OVERVIEW_CACHE_TTL: Duration = Duration::from_secs(5);

/// How many collection intervals pass between SSE aggregate refreshes.
/// Flows still ride every tick; the endpoint/domain/application summaries are
/// whole-history scans, and the lists that consume them refresh on their own
/// cadence anyway.
const AGGREGATE_TICKS: u64 = 3;
const TOP_LIST_LIMIT: usize = 10;
/// Upper bound on aggregate rows embedded in one SSE tick. Overflow is
/// recovered by the client's periodic full refresh.
const TICK_AGGREGATE_LIMIT: usize = 256;
const AUDIT_CAPACITY: usize = 32;
const MINUTE_BUCKET_RETENTION_MS: i64 = 2 * 60 * 60 * 1000;
const HOUR_BUCKET_RETENTION_MS: i64 = 8 * 24 * 60 * 60 * 1000;
const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;

const SCHEMA_VERSION: i64 = 8;

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
    domains_json TEXT NOT NULL DEFAULT '[]',
    service TEXT,
    app_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows(last_seen_ms);
CREATE INDEX IF NOT EXISTS idx_flows_remote ON flows(remote_addr);
CREATE INDEX IF NOT EXISTS idx_flows_state ON flows(state);
CREATE INDEX IF NOT EXISTS idx_flows_app_id ON flows(app_id);

CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    exe TEXT,
    comm TEXT,
    uid INTEGER,
    container_id TEXT,
    first_seen_ms INTEGER NOT NULL,
    last_seen_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_applications_last_seen ON applications(last_seen_ms);

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

CREATE TABLE IF NOT EXISTS entity_buckets (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    resolution TEXT NOT NULL,
    start_ms INTEGER NOT NULL,
    in_packets INTEGER NOT NULL,
    in_bytes INTEGER NOT NULL,
    out_packets INTEGER NOT NULL,
    out_bytes INTEGER NOT NULL,
    PRIMARY KEY (kind, key, resolution, start_ms)
);

CREATE TABLE IF NOT EXISTS entity_rates (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    inbound_bps INTEGER NOT NULL,
    outbound_bps INTEGER NOT NULL,
    PRIMARY KEY (kind, key)
) WITHOUT ROWID;

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
"#;

const FLOW_COLUMNS: &str = "id, direction, protocol, src_addr, src_port, dst_addr, dst_port, \
     ifindex, interface, packets, bytes, first_seen_ms, last_seen_ms, state, end_reason, \
     remote_addr, remote_port, remote_scope, remote_country, remote_region, remote_city, \
     remote_asn, remote_org, remote_db_version, remote_enriched_at_ms, domains_json, service, \
     app_id, \
     (SELECT name FROM applications WHERE applications.id = flows.app_id) AS app_name, \
     (SELECT kind FROM applications WHERE applications.id = flows.app_id) AS app_kind";

/// Aggregate projection of Flows grouped by `flows.app_id`, joined to the
/// Application record for display metadata.
const APPLICATION_COLUMNS: &str = "flows.app_id AS app_id, \
     MAX(a.name) AS app_name, MAX(a.kind) AS app_kind, MAX(a.exe) AS app_exe, \
     MAX(a.comm) AS app_comm, MAX(a.uid) AS app_uid, MAX(a.container_id) AS app_container_id, \
     SUM(flows.packets) AS total_packets, SUM(flows.bytes) AS total_bytes, \
     COALESCE(SUM(CASE WHEN flows.direction = 'inbound' THEN flows.packets ELSE 0 END), 0) \
         AS in_packets, \
     COALESCE(SUM(CASE WHEN flows.direction = 'inbound' THEN flows.bytes ELSE 0 END), 0) \
         AS in_bytes, \
     COALESCE(SUM(CASE WHEN flows.direction = 'outbound' THEN flows.packets ELSE 0 END), 0) \
         AS out_packets, \
     COALESCE(SUM(CASE WHEN flows.direction = 'outbound' THEN flows.bytes ELSE 0 END), 0) \
         AS out_bytes, \
     COUNT(*) AS flow_count, MIN(flows.first_seen_ms) AS first_seen_ms, \
     MAX(flows.last_seen_ms) AS last_seen_ms";

/// Canonical unordered endpoint pair of a connection, as SQL expressions.
const PAIR_LO: &str =
    "MIN(src_addr || ':' || COALESCE(src_port, -1), dst_addr || ':' || COALESCE(dst_port, -1))";
const PAIR_HI: &str =
    "MAX(src_addr || ':' || COALESCE(src_port, -1), dst_addr || ':' || COALESCE(dst_port, -1))";

/// Runtime configuration for the API state.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub version: String,
    pub flow_capacity: usize,
    pub export_ttl: Duration,
    pub geoip_database: Option<PathBuf>,
    /// SQLite file; `None` keeps a private in-memory database.
    pub database: Option<PathBuf>,
    /// Fingerprint library shared with the collector.
    pub fingerprints: SharedFingerprints,
    /// Where uploaded fingerprints are persisted; `None` keeps them in memory.
    pub fingerprints_path: Option<PathBuf>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            flow_capacity: 65_536,
            export_ttl: Duration::from_secs(24 * 60 * 60),
            geoip_database: None,
            database: None,
            fingerprints: crate::collector::fingerprint::shared_default(),
            fingerprints_path: None,
        }
    }
}

/// Number of trailing collection intervals a reported rate averages over.
pub(crate) const RATE_WINDOW_TICKS: usize = 5;

/// Trailing byte window for one direction: `(bytes, interval seconds)` samples.
///
/// Every collection interval starts a new sample, zero bytes when the entity
/// was idle, so a burst decays over the window instead of dropping straight to
/// zero after one quiet second.
#[derive(Clone, Debug, Default)]
struct RateWindow {
    samples: VecDeque<(u64, f64)>,
    bytes: u64,
    seconds: f64,
}

impl RateWindow {
    fn push(&mut self, bytes: u64, interval_seconds: f64) {
        self.samples.push_back((bytes, interval_seconds));
        self.bytes = self.bytes.saturating_add(bytes);
        self.seconds += interval_seconds;
        while self.samples.len() > RATE_WINDOW_TICKS {
            let (old_bytes, old_seconds) = self.samples.pop_front().expect("window sample");
            self.bytes = self.bytes.saturating_sub(old_bytes);
            self.seconds -= old_seconds;
        }
    }

    /// Adds bytes to the newest sample; [`EntityRates::roll`] must have started it.
    fn add_bytes(&mut self, bytes: u64) {
        if let Some(sample) = self.samples.back_mut() {
            sample.0 = sample.0.saturating_add(bytes);
        }
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn bps(&self) -> u64 {
        if self.seconds > 0.0 {
            (self.bytes as f64 * 8.0 / self.seconds) as u64
        } else {
            0
        }
    }
}

/// Trailing rates of one entity over the last [`RATE_WINDOW_TICKS`] intervals.
#[derive(Clone, Debug, Default)]
struct EntityRates {
    inbound: RateWindow,
    outbound: RateWindow,
}

impl EntityRates {
    /// An entity first seen this interval, with its newest sample started.
    fn started(interval_seconds: f64) -> Self {
        let mut rates = Self::default();
        rates.roll(interval_seconds);
        rates
    }

    /// Starts the next interval sample for both directions.
    fn roll(&mut self, interval_seconds: f64) {
        self.inbound.push(0, interval_seconds);
        self.outbound.push(0, interval_seconds);
    }

    /// Adds one interval's bytes to the newest sample.
    fn add(&mut self, direction: FlowDirection, bytes: u64) {
        match direction {
            FlowDirection::Inbound => self.inbound.add_bytes(bytes),
            FlowDirection::Outbound => self.outbound.add_bytes(bytes),
        }
    }

    fn inbound_bps(&self) -> u64 {
        self.inbound.bps()
    }

    fn outbound_bps(&self) -> u64 {
        self.outbound.bps()
    }

    /// Whether the window still carries traffic; idle entities are evicted.
    fn is_active(&self) -> bool {
        self.inbound.bytes > 0 || self.outbound.bytes > 0
    }
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
    /// Refreshed aggregates for every remote peer touched by this interval.
    pub endpoints: Vec<EndpointSummaryDto>,
    /// Refreshed aggregates for every Associated Domain touched by this
    /// interval.
    pub domain_summaries: Vec<DomainSummaryDto>,
    /// Refreshed aggregates for every Application touched by this interval.
    pub applications: Vec<ApplicationSummaryDto>,
    /// New or refreshed domain associations observed in the interval.
    pub observations: Vec<DomainObservationDto>,
    pub overview: TickOverviewDto,
    pub health: CollectorHealthDto,
    /// Serialized tick payloads keyed by subscriber filter, so several idle
    /// subscribers share one JSON encoding per interval.
    tick_cache: Mutex<HashMap<String, Arc<str>>>,
}

impl StreamEvent {
    /// Serializes this interval for one subscriber filter, computing the JSON
    /// at most once per distinct filter set.
    pub(crate) fn tick_json(&self, filter: &super::dto::StreamFilter) -> Option<Arc<str>> {
        let key = filter.cache_key();
        if let Ok(cache) = self.tick_cache.lock() {
            if let Some(data) = cache.get(&key) {
                return Some(Arc::clone(data));
            }
        }
        let data: Arc<str> = serde_json::to_string(&self.tick(filter)).ok()?.into();
        if let Ok(mut cache) = self.tick_cache.lock() {
            cache.insert(key, Arc::clone(&data));
        }
        Some(data)
    }

    /// Projects the interval into a filtered `tick` payload.
    ///
    /// Aggregate lists are keyed by the filtered Flows: a subscriber only
    /// receives endpoint and domain summaries that its filter can observe.
    pub(crate) fn tick(&self, filter: &super::dto::StreamFilter) -> TickDto {
        let flows: Vec<FlowDto> = self
            .flows
            .iter()
            .filter(|flow| filter.matches(flow))
            .cloned()
            .collect();
        let endpoints: Vec<EndpointSummaryDto> = {
            let keys: HashSet<&str> = flows
                .iter()
                .map(|flow| flow.remote.address.as_str())
                .collect();
            self.endpoints
                .iter()
                .filter(|endpoint| keys.contains(endpoint.address.as_str()))
                .cloned()
                .collect()
        };
        let domain_summaries: Vec<DomainSummaryDto> = {
            let keys: HashSet<&str> = flows
                .iter()
                .flat_map(|flow| flow.domains.iter().map(|domain| domain.domain.as_str()))
                .collect();
            self.domain_summaries
                .iter()
                .filter(|domain| keys.contains(domain.domain.as_str()))
                .cloned()
                .collect()
        };
        let applications: Vec<ApplicationSummaryDto> = {
            let keys: HashSet<&str> = flows
                .iter()
                .filter_map(|flow| flow.application.as_ref().map(|app| app.id.as_str()))
                .collect();
            self.applications
                .iter()
                .filter(|application| keys.contains(application.id.as_str()))
                .cloned()
                .collect()
        };

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
            flows,
            endpoints,
            domains: domain_summaries,
            applications,
            observations: self
                .observations
                .iter()
                .filter(|observation| filter.matches_domain(&observation.domain))
                .cloned()
                .collect(),
            overview: self.overview,
            health: Some(self.health.clone()),
        }
    }
}

pub(crate) struct ExportContent {
    pub content_type: String,
    pub file_name: String,
    pub bytes: Vec<u8>,
}

/// One persisted Traffic Rule plus its storage timestamps.
#[derive(Clone, Debug)]
pub(crate) struct TrafficRuleRecord {
    pub rule: TrafficRule,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

/// A rule about to be persisted; storage assigns the id.
#[derive(Clone, Debug)]
pub(crate) struct TrafficRuleDraft {
    pub action: ActionSpec,
    pub direction: RuleDirection,
    pub selector: Selector,
    pub enabled: bool,
}

/// SQLite connection plus live state that does not belong in the database.
pub(crate) struct Db {
    conn: Connection,
    enricher: Enricher,
    applications: ApplicationResolver,
    enrichment_error: Option<String>,
    database_error: Option<String>,
    interfaces: HashMap<u32, Box<str>>,
    health: Option<CollectorHealth>,
    last_batch_at: Option<SystemTime>,
    last_interval: Duration,
    batch_sequence: u64,
    rates: EntityRates,
    /// Trailing rate windows keyed per entity. They are live read-model
    /// state, not persisted history: an entity idle for a whole window reads
    /// zero and is evicted.
    rates_by_flow: HashMap<u64, EntityRates>,
    rates_by_connection: HashMap<String, EntityRates>,
    rates_by_endpoint: HashMap<String, EntityRates>,
    rates_by_domain: HashMap<String, EntityRates>,
    rates_by_application: HashMap<String, EntityRates>,
    audit: VecDeque<AuditEntry>,
    export_counter: u64,
    export_ttl: Duration,
    flow_capacity: usize,
    /// Retention and capacity deletes run on this cadence instead of once per
    /// collection interval; the table is capped, so a few seconds of slack is
    /// invisible while the full-table scans are not.
    last_policy_at: Option<Instant>,
    /// `tick_overview` counters change slowly and scan the whole table; cache
    /// them for a few intervals.
    overview_cache: Option<(Instant, TickOverviewDto)>,
    /// Monotonic token for Traffic Rule changes; applied programs carry it.
    rules_revision: u64,
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
        let mut db = Self::from_connection(conn, config)?;
        if let Err(error) = db.backfill_enrichment() {
            db.enrichment_error = Some(format!("geoip backfill failed: {error}"));
        }
        Ok(db)
    }

    fn from_connection(conn: Connection, config: &ApiConfig) -> anyhow::Result<Self> {
        let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        register_functions(&conn)?;

        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < SCHEMA_VERSION {
            // Pre-release shortcut: schema v7 replaces the per-kind rule
            // columns with one `selector_json` column, so old rule rows are
            // recreated instead of migrated (ADR-0005).
            if version > 0 && version < 7 {
                conn.execute_batch("DROP TABLE IF EXISTS traffic_rules")?;
            }
            conn.execute_batch(SCHEMA_SQL)?;
            // Upgraded databases keep their rows: new columns are added in
            // place instead of recreating tables.
            add_column_if_missing(&conn, "flows", "service", "TEXT")?;
            add_column_if_missing(&conn, "flows", "app_id", "TEXT")?;
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
            applications: ApplicationResolver::default(),
            enrichment_error,
            database_error: None,
            interfaces: HashMap::new(),
            health: None,
            last_batch_at: None,
            last_interval: Duration::from_secs(1),
            batch_sequence: 0,
            rates: EntityRates::default(),
            rates_by_flow: HashMap::new(),
            rates_by_connection: HashMap::new(),
            rates_by_endpoint: HashMap::new(),
            rates_by_domain: HashMap::new(),
            rates_by_application: HashMap::new(),
            audit: VecDeque::new(),
            export_counter: 0,
            export_ttl: config.export_ttl,
            flow_capacity: config.flow_capacity.max(1),
            last_policy_at: None,
            overview_cache: None,
            rules_revision: 0,
        })
    }

    // ----------------------------------------------------------------- ingest

    pub(crate) fn ingest(
        &mut self,
        batch: CollectionBatch,
        settings: &Settings,
        proxy: &ProxyResolver,
        publish: bool,
    ) -> StreamEvent {
        let sequence = batch.sequence;
        let collected_at = batch.collected_at;
        let interval = batch.interval;
        let health = CollectorHealthDto::from_health(&batch.health);
        match self.try_ingest(batch, settings, proxy, publish) {
            Ok(event) => event,
            Err(error) => {
                eprintln!("zimascoped: storage ingest failed: {error}");
                self.database_error = Some(error.to_string());
                StreamEvent {
                    sequence,
                    collected_at,
                    interval,
                    inbound: TrafficCounters::default(),
                    outbound: TrafficCounters::default(),
                    inbound_bps: self.rates.inbound_bps(),
                    outbound_bps: self.rates.outbound_bps(),
                    flows: Vec::new(),
                    endpoints: Vec::new(),
                    domain_summaries: Vec::new(),
                    applications: Vec::new(),
                    observations: Vec::new(),
                    overview: TickOverviewDto::default(),
                    health,
                    tick_cache: Mutex::new(HashMap::new()),
                }
            }
        }
    }

    fn try_ingest(
        &mut self,
        batch: CollectionBatch,
        settings: &Settings,
        proxy: &ProxyResolver,
        publish: bool,
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
        self.roll_entity_rates(seconds);
        self.rates.roll(seconds);
        self.rates.add(FlowDirection::Inbound, inbound.bytes);
        self.rates.add(FlowDirection::Outbound, outbound.bytes);

        let mut touched: Vec<u64> = Vec::new();
        let mut domain_events: Vec<DomainObservationDto> = Vec::new();
        let mut changed_addresses: HashSet<IpAddr> = HashSet::new();
        let mut flow_deltas: HashMap<u64, (FlowDirection, TrafficCounters)> = HashMap::new();

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

            for address in &changed_addresses {
                let domains_json = associate_address(&tx, *address, now_system)?;
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

            let mut writer = FlowWriter {
                enricher: &mut self.enricher,
                applications: &mut self.applications,
                interfaces: &self.interfaces,
                proxy,
            };
            for update in flows {
                let id = flow_id(&update.key);
                flow_deltas.insert(id, (update.key.direction, update.delta));
                upsert_flow(&tx, id, &update, now_instant, now_system, &mut writer)?;
                touched.push(id);

                if update.delta.bytes > 0 {
                    self.rates_by_flow
                        .entry(id)
                        .or_insert_with(|| EntityRates::started(seconds))
                        .add(update.key.direction, update.delta.bytes);
                    let (pair_lo, pair_hi) = connection_pair(&update.key);
                    let connection = connection_id(
                        update.key.protocol,
                        i64::from(update.key.interface_index.get()),
                        &pair_lo,
                        &pair_hi,
                    );
                    self.rates_by_connection
                        .entry(connection)
                        .or_insert_with(|| EntityRates::started(seconds))
                        .add(update.key.direction, update.delta.bytes);
                }
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
        let mut updated: Vec<(u64, FlowDto)> = Vec::new();
        for id in touched {
            if let Some(dto) = self.flow_by_id(id)? {
                updated.push((id, dto));
            }
        }

        for (id, dto) in &updated {
            let Some((direction, delta)) = flow_deltas.get(id) else {
                continue;
            };
            if delta.bytes == 0 {
                continue;
            }
            self.rates_by_endpoint
                .entry(dto.remote.address.clone())
                .or_insert_with(|| EntityRates::started(seconds))
                .add(*direction, delta.bytes);
            if let Some(application) = &dto.application {
                self.rates_by_application
                    .entry(application.id.clone())
                    .or_insert_with(|| EntityRates::started(seconds))
                    .add(*direction, delta.bytes);
            }
            for domain in &dto.domains {
                self.rates_by_domain
                    .entry(domain.domain.clone())
                    .or_insert_with(|| EntityRates::started(seconds))
                    .add(*direction, delta.bytes);
            }
        }

        if !flow_deltas.is_empty() {
            let tx = self.conn.transaction()?;
            let minute = truncate_time(collected_at, 60);
            let hour = truncate_time(collected_at, 3600);
            for (id, dto) in &updated {
                let Some((direction, delta)) = flow_deltas.get(id) else {
                    continue;
                };
                if delta.packets == 0 && delta.bytes == 0 {
                    continue;
                }
                for (resolution, start) in [("minute", minute), ("hour", hour)] {
                    add_entity_bucket(
                        &tx,
                        "endpoint",
                        &dto.remote.address,
                        resolution,
                        start,
                        *direction,
                        *delta,
                    )?;
                    if let Some(application) = &dto.application {
                        add_entity_bucket(
                            &tx,
                            "application",
                            &application.id,
                            resolution,
                            start,
                            *direction,
                            *delta,
                        )?;
                    }
                    for domain in &dto.domains {
                        add_entity_bucket(
                            &tx,
                            "domain",
                            &domain.domain,
                            resolution,
                            start,
                            *direction,
                            *delta,
                        )?;
                    }
                }
            }
            tx.commit()?;
        }

        self.store_entity_rates()?;

        let mut touched_addresses: HashSet<String> =
            changed_addresses.iter().map(ToString::to_string).collect();
        let mut touched_domains: HashSet<String> = domain_events
            .iter()
            .map(|event| event.domain.clone())
            .collect();
        let mut touched_applications: HashSet<String> = HashSet::new();
        for (_, flow) in &updated {
            touched_addresses.insert(flow.remote.address.clone());
            if let Some(application) = &flow.application {
                touched_applications.insert(application.id.clone());
            }
            for domain in &flow.domains {
                touched_domains.insert(domain.domain.clone());
            }
        }

        // Aggregates only matter to live subscribers and only every few
        // intervals: the whole-history scans are the most expensive part of
        // the pipeline, while Flows themselves still ride every tick.
        let aggregate = publish && sequence.saturating_sub(1) % AGGREGATE_TICKS == 0;
        let (endpoints, domain_summaries, applications, overview) = if aggregate {
            (
                self.endpoint_summaries_for(&touched_addresses)?,
                self.domain_summaries_for(&touched_domains)?,
                self.application_summaries_for(&touched_applications)?,
                self.tick_overview()?,
            )
        } else {
            (
                Vec::new(),
                Vec::new(),
                Vec::new(),
                TickOverviewDto::default(),
            )
        };

        Ok(StreamEvent {
            sequence,
            collected_at,
            interval,
            inbound,
            outbound,
            inbound_bps: self.rates.inbound_bps(),
            outbound_bps: self.rates.outbound_bps(),
            flows: updated.into_iter().map(|(_, dto)| dto).collect(),
            endpoints,
            domain_summaries,
            applications,
            observations: domain_events,
            overview,
            health: health_dto,
            tick_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Advances every entity rate window by one interval and evicts entries
    /// whose traffic has aged out of the window.
    fn roll_entity_rates(&mut self, interval_seconds: f64) {
        for rates in self.rates_by_flow.values_mut() {
            rates.roll(interval_seconds);
        }
        self.rates_by_flow.retain(|_, rates| rates.is_active());
        for rates in self.rates_by_connection.values_mut() {
            rates.roll(interval_seconds);
        }
        self.rates_by_connection
            .retain(|_, rates| rates.is_active());
        for rates in self.rates_by_endpoint.values_mut() {
            rates.roll(interval_seconds);
        }
        self.rates_by_endpoint.retain(|_, rates| rates.is_active());
        for rates in self.rates_by_domain.values_mut() {
            rates.roll(interval_seconds);
        }
        self.rates_by_domain.retain(|_, rates| rates.is_active());
        for rates in self.rates_by_application.values_mut() {
            rates.roll(interval_seconds);
        }
        self.rates_by_application
            .retain(|_, rates| rates.is_active());
    }

    /// Persists the latest interval's entity rates so list queries can sort by
    /// them with plain SQL. The table mirrors the in-memory maps exactly:
    /// stale rows are cleared, then the current interval is written.
    fn store_entity_rates(&mut self) -> Result<(), ApiError> {
        let tx = self.conn.transaction()?;
        tx.execute("DELETE FROM entity_rates", [])?;
        {
            let mut statement = tx.prepare(
                "INSERT INTO entity_rates (kind, key, inbound_bps, outbound_bps) \
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            let mut insert = |kind: &str, key: &str, rate: &EntityRates| -> rusqlite::Result<()> {
                statement.execute(params![
                    kind,
                    key,
                    rate.inbound_bps() as i64,
                    rate.outbound_bps() as i64,
                ])?;
                Ok(())
            };
            for (id, rate) in &self.rates_by_flow {
                insert("flow", &id.to_string(), rate)?;
            }
            for (id, rate) in &self.rates_by_connection {
                insert("connection", id, rate)?;
            }
            for (address, rate) in &self.rates_by_endpoint {
                insert("endpoint", address, rate)?;
            }
            for (domain, rate) in &self.rates_by_domain {
                insert("domain", domain, rate)?;
            }
            for (id, rate) in &self.rates_by_application {
                insert("application", id, rate)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    fn enforce_policy(&mut self, settings: &Settings, now: SystemTime) -> Result<(), ApiError> {
        self.flow_capacity = settings.resources.max_flow_entries as usize;
        let now_instant = Instant::now();
        if let Some(last) = self.last_policy_at {
            if now_instant.saturating_duration_since(last) < POLICY_INTERVAL {
                return Ok(());
            }
        }
        self.last_policy_at = Some(now_instant);
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
            self.conn
                .execute("DELETE FROM applications WHERE last_seen_ms < ?1", [cutoff])?;
        } else {
            self.conn
                .execute("DELETE FROM flows WHERE state = 'ended'", [])?;
            self.conn.execute(
                "DELETE FROM applications WHERE id NOT IN (SELECT DISTINCT app_id FROM flows \
                 WHERE app_id IS NOT NULL)",
                [],
            )?;
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
        self.conn.execute(
            "DELETE FROM entity_buckets WHERE resolution = 'minute' AND start_ms < ?1",
            [now_ms - MINUTE_BUCKET_RETENTION_MS],
        )?;
        self.conn.execute(
            "DELETE FROM entity_buckets WHERE resolution = 'hour' AND start_ms < ?1",
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
        let dto = self
            .conn
            .query_row(&sql, [id as i64], flow_dto_from_row)
            .optional()?;
        Ok(dto.map(|mut dto| {
            self.apply_flow_rate(&mut dto);
            dto
        }))
    }

    /// Overwrites the DTO's rate fields from the live interval maps. A missing
    /// entry means the entity carried no traffic in the latest interval.
    fn apply_flow_rate(&self, dto: &mut FlowDto) {
        if let Ok(id) = u64::from_str_radix(&dto.id, 16) {
            if let Some(rate) = self.rates_by_flow.get(&id) {
                dto.inbound_bps = rate.inbound_bps();
                dto.outbound_bps = rate.outbound_bps();
            }
        }
    }

    fn apply_endpoint_rate(&self, dto: &mut EndpointSummaryDto) {
        if let Some(rate) = self.rates_by_endpoint.get(&dto.address) {
            dto.inbound_bps = rate.inbound_bps();
            dto.outbound_bps = rate.outbound_bps();
        }
    }

    fn apply_domain_rate(&self, dto: &mut DomainSummaryDto) {
        if let Some(rate) = self.rates_by_domain.get(&dto.domain) {
            dto.inbound_bps = rate.inbound_bps();
            dto.outbound_bps = rate.outbound_bps();
        }
    }

    fn apply_application_rate(&self, dto: &mut ApplicationSummaryDto) {
        if let Some(rate) = self.rates_by_application.get(&dto.id) {
            dto.inbound_bps = rate.inbound_bps();
            dto.outbound_bps = rate.outbound_bps();
        }
    }

    // ---------------------------------------------------------- applications

    pub(crate) fn list_applications(
        &self,
        query: &FlowQuery,
    ) -> Result<Page<ApplicationSummaryDto>, ApiError> {
        let limit = page_limit(query.limit)?;
        let offset = query.offset.unwrap_or(0);
        let (items, total) = self.application_rows(query, limit, offset)?;
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    pub(crate) fn get_application(&self, id: &str) -> Result<ApplicationDetailDto, ApiError> {
        if id.trim().is_empty() {
            return Err(ApiError::bad_request("application id must not be empty"));
        }
        let query = FlowQuery {
            application_id: Some(id.to_owned()),
            ..FlowQuery::default()
        };
        let (summaries, _) = self.application_rows(&query, 1, 0)?;
        let summary = summaries
            .into_iter()
            .next()
            .ok_or_else(|| ApiError::not_found(format!("no Flow observed for application {id}")))?;

        let mut statement = self
            .conn
            .prepare("SELECT domains_json FROM flows WHERE app_id = ?1")?;
        let mut domains: Vec<DomainRefDto> = Vec::new();
        for row in statement.query_map([id], |row| row.get::<_, String>(0))? {
            let parsed: Vec<DomainRefDto> = serde_json::from_str(&row?).unwrap_or_default();
            for association in parsed {
                push_domain(&mut domains, &association);
            }
        }
        domains.sort_by(|left, right| left.domain.cmp(&right.domain));
        let destinations = self.application_destinations(id)?;

        Ok(ApplicationDetailDto {
            id: summary.id.clone(),
            name: summary.name,
            kind: summary.kind,
            exe: summary.exe,
            comm: summary.comm,
            uid: summary.uid,
            container_id: summary.container_id,
            packets: summary.packets,
            bytes: summary.bytes,
            traffic: summary.traffic,
            flow_count: summary.flow_count,
            first_seen: summary.first_seen,
            last_seen: summary.last_seen,
            domains,
            destinations,
            flows_url: format!("/v1/flows?application_id={}", encode_uri_component(id)),
        })
    }

    /// Aggregates one Application's Flows by peer address and attaches the
    /// Associated Domains observed for that address inside this Application.
    fn application_destinations(
        &self,
        id: &str,
    ) -> Result<Vec<ApplicationDestinationDto>, ApiError> {
        let mut domains_by_address: HashMap<String, Vec<DomainRefDto>> = HashMap::new();
        {
            let mut statement = self.conn.prepare(
                "SELECT flows.remote_addr, je.value->>'domain', je.value->>'evidence', \
                 je.value->>'confidence' FROM flows, json_each(flows.domains_json) je \
                 WHERE flows.app_id = ?1 AND je.value->>'domain' IS NOT NULL",
            )?;
            let rows = statement.query_map([id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (address, domain, evidence, confidence) = row?;
                let Some(evidence) = enum_from_value::<DomainEvidence>(&evidence) else {
                    continue;
                };
                let Some(confidence) = enum_from_value::<AssociationConfidence>(&confidence) else {
                    continue;
                };
                push_domain(
                    domains_by_address.entry(address).or_default(),
                    &DomainRefDto {
                        domain,
                        evidence,
                        confidence,
                    },
                );
            }
        }

        let mut statement = self.conn.prepare(
            "SELECT remote_addr, MAX(remote_scope), MAX(remote_country), MAX(remote_asn), \
             MAX(remote_org), SUM(packets), SUM(bytes), \
             COALESCE(SUM(CASE WHEN direction = 'inbound' THEN packets ELSE 0 END), 0), \
             COALESCE(SUM(CASE WHEN direction = 'inbound' THEN bytes ELSE 0 END), 0), \
             COALESCE(SUM(CASE WHEN direction = 'outbound' THEN packets ELSE 0 END), 0), \
             COALESCE(SUM(CASE WHEN direction = 'outbound' THEN bytes ELSE 0 END), 0), \
             COUNT(*) FROM flows WHERE app_id = ?1 GROUP BY remote_addr \
             ORDER BY SUM(bytes) DESC, remote_addr LIMIT ?2",
        )?;
        let mut destinations = statement
            .query_map(params![id, MAX_APPLICATION_DESTINATIONS as i64], |row| {
                let scope: String = row.get(1)?;
                Ok(ApplicationDestinationDto {
                    address: row.get(0)?,
                    scope: enum_from_value(&scope).unwrap_or(AddressScope::Reserved),
                    country: row.get(2)?,
                    asn: row.get(3)?,
                    organization: row.get(4)?,
                    packets: row.get::<_, i64>(5)? as u64,
                    bytes: row.get::<_, i64>(6)? as u64,
                    traffic: DirectionTotalsDto {
                        inbound: CountersDto {
                            packets: row.get::<_, i64>(7)? as u64,
                            bytes: row.get::<_, i64>(8)? as u64,
                        },
                        outbound: CountersDto {
                            packets: row.get::<_, i64>(9)? as u64,
                            bytes: row.get::<_, i64>(10)? as u64,
                        },
                    },
                    flow_count: row.get::<_, i64>(11)? as u64,
                    domains: Vec::new(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        for destination in &mut destinations {
            if let Some(mut domains) = domains_by_address.remove(&destination.address) {
                domains.sort_by(|left, right| left.domain.cmp(&right.domain));
                destination.domains = domains;
            }
        }

        Ok(destinations)
    }

    pub(crate) fn application_timeline(
        &self,
        id: &str,
        range: TimeRange,
        now: SystemTime,
    ) -> Result<TimelineDto, ApiError> {
        self.buckets_timeline(range, now, Some(("application", id)))
    }

    fn application_rows(
        &self,
        query: &FlowQuery,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<ApplicationSummaryDto>, usize), ApiError> {
        let now = SystemTime::now();
        let mut row_query = query.clone();
        let search = row_query
            .q
            .take()
            .map(|q| q.trim().to_ascii_lowercase())
            .filter(|q| !q.is_empty());
        let (mut clauses, mut params) = self.flow_clauses(&row_query, now, "flows.", false)?;
        clauses.push("flows.app_id IS NOT NULL".to_owned());
        if let Some(search) = search {
            clauses.push(
                "instr(lower(coalesce(a.name, '') || ' ' || coalesce(a.exe, '') || ' ' || \
                 coalesce(a.comm, '') || ' ' || coalesce(flows.app_id, '')), ?) > 0"
                    .to_owned(),
            );
            params.push(Value::Text(search));
        }
        let where_clause = where_sql(&clauses);

        let total: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM (SELECT 1 FROM flows LEFT JOIN applications a \
                 ON a.id = flows.app_id {where_clause} GROUP BY flows.app_id)"
            ),
            params_from_iter(params.clone()),
            |row| row.get(0),
        )?;

        let order = application_order(query.sort.as_deref())?;
        let sql = format!(
            "SELECT {APPLICATION_COLUMNS} FROM flows LEFT JOIN applications a \
             ON a.id = flows.app_id {where_clause} GROUP BY flows.app_id \
             ORDER BY {order} LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let mut items = statement
            .query_map(params_from_iter(params), application_summary_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_application_rate(item);
        }
        Ok((items, total as usize))
    }

    /// Refreshed Application summaries for the given ids, used by the SSE tick
    /// so Application lists update without polling.
    fn application_summaries_for(
        &self,
        applications: &HashSet<String>,
    ) -> Result<Vec<ApplicationSummaryDto>, ApiError> {
        if applications.is_empty() {
            return Ok(Vec::new());
        }
        let keys = json_key_list(applications.iter())?;
        let mut statement = self.conn.prepare(&format!(
            "SELECT {APPLICATION_COLUMNS} FROM flows LEFT JOIN applications a \
             ON a.id = flows.app_id \
             WHERE flows.app_id IN (SELECT value FROM json_each(?1)) \
             GROUP BY flows.app_id ORDER BY total_bytes DESC, flows.app_id LIMIT ?2"
        ))?;
        let mut items = statement
            .query_map(
                params![keys, TICK_AGGREGATE_LIMIT as i64],
                application_summary_from_row,
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_application_rate(item);
        }
        Ok(items)
    }

    // ------------------------------------------------------------ connections

    /// Merges directional Flows into one record per unordered endpoint pair.
    ///
    /// `direction` is ignored (a connection has no single direction) and
    /// `state` is evaluated on the aggregate. `hide_noise` drops DNS pairs
    /// and sub-second chatter.
    pub(crate) fn list_connections(
        &self,
        query: &FlowQuery,
    ) -> Result<Page<ConnectionDto>, ApiError> {
        let limit = page_limit(query.limit)?;
        let offset = query.offset.unwrap_or(0);
        let now = SystemTime::now();

        let mut row_query = query.clone();
        row_query.direction = None;
        row_query.state = None;
        // Service is a property of the merged pair, not of one directional
        // row: filtering the WHERE would drop the other direction from the
        // totals, so it is applied after aggregation instead.
        let service = row_query.service.take();
        let (clauses, mut params) = self.flow_clauses(&row_query, now, "", true)?;
        if let Some(service) = &service {
            params.push(Value::Text(service.clone()));
        }
        let where_clause = where_sql(&clauses);

        let mut havings: Vec<String> = Vec::new();
        if service.is_some() {
            havings.push("MAX(service) = ? COLLATE NOCASE".to_owned());
        }
        match query.state {
            Some(FlowStateParam::Active) => {
                havings.push("SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) > 0".to_owned())
            }
            Some(FlowStateParam::Ended) => {
                havings.push("SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) = 0".to_owned())
            }
            None => {}
        }
        if query.hide_noise.unwrap_or(false) {
            havings.push(
                "SUM(CASE WHEN src_port = 53 OR dst_port = 53 THEN 1 ELSE 0 END) = 0".to_owned(),
            );
            havings.push("(MAX(last_seen_ms) - MIN(first_seen_ms)) >= 1000".to_owned());
        }
        let having_clause = if havings.is_empty() {
            String::new()
        } else {
            format!("HAVING {}", havings.join(" AND "))
        };

        let total: i64 = self.conn.query_row(
            &format!(
                "SELECT COUNT(*) FROM (SELECT 1 FROM flows {where_clause} \
                 GROUP BY protocol, ifindex, {PAIR_LO}, {PAIR_HI} {having_clause})"
            ),
            params_from_iter(params.clone()),
            |row| row.get(0),
        )?;

        let order = connection_order(query.sort.as_deref())?;
        let sql = format!(
            "SELECT protocol, ifindex, {PAIR_LO} AS pair_lo, {PAIR_HI} AS pair_hi, \
             MAX(interface), MAX(remote_addr) AS remote_addr, MAX(remote_port), \
             MAX(remote_scope), \
             MAX(remote_country), MAX(remote_region), MAX(remote_city), MAX(remote_asn), \
             MAX(remote_org), MAX(remote_db_version), MAX(remote_enriched_at_ms), \
             MAX(CASE WHEN direction = 'outbound' THEN src_addr ELSE dst_addr END) AS host_addr, \
             MAX(CASE WHEN direction = 'outbound' THEN src_port ELSE dst_port END) AS host_port, \
             SUM(packets) AS total_packets, SUM(bytes) AS total_bytes, \
             SUM(CASE WHEN direction = 'inbound' THEN packets ELSE 0 END) AS in_packets, \
             SUM(CASE WHEN direction = 'inbound' THEN bytes ELSE 0 END) AS in_bytes, \
             SUM(CASE WHEN direction = 'outbound' THEN packets ELSE 0 END) AS out_packets, \
             SUM(CASE WHEN direction = 'outbound' THEN bytes ELSE 0 END) AS out_bytes, \
             MAX(end_reason), \
             SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) AS active_rows, \
             MIN(first_seen_ms) AS first_seen_ms, MAX(last_seen_ms) AS last_seen_ms, \
             (MAX(last_seen_ms) - MIN(first_seen_ms)) AS duration_ms, \
             MAX(service) AS service, \
             MIN(json_extract(domains_json, '$[0].domain')) AS first_domain, \
             json_group_array(domains_json) AS domains_all \
             FROM flows {where_clause} \
             GROUP BY protocol, ifindex, pair_lo, pair_hi {having_clause} \
             ORDER BY {order} LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement
            .query_map(params_from_iter(params), |row| {
                let protocol: String = row.get(0)?;
                let ifindex: i64 = row.get(1)?;
                let pair_lo: String = row.get(2)?;
                let pair_hi: String = row.get(3)?;
                let scope: String = row.get(7)?;
                let active_rows: i64 = row.get(24)?;
                let protocol: Protocol =
                    enum_from_value(&protocol).ok_or_else(|| invalid_enum("protocol"))?;
                let state = if active_rows > 0 { "active" } else { "ended" };
                let remote_address: String = row.get(5)?;
                let host_port = row.get::<_, Option<i64>>(16)?.map(|port| port as u16);
                let remote_port = row.get::<_, Option<i64>>(6)?.map(|port| port as u16);
                Ok((
                    ConnectionDto {
                        id: connection_id(protocol, ifindex, &pair_lo, &pair_hi),
                        protocol,
                        service: row.get(28)?,
                        state,
                        end_reason: row
                            .get::<_, Option<String>>(23)?
                            .as_deref()
                            .and_then(enum_from_value),
                        host: EndpointDto {
                            address: row.get(15)?,
                            port: host_port,
                        },
                        remote: EndpointDto {
                            address: remote_address.clone(),
                            port: remote_port,
                        },
                        remote_profile: IpProfileDto {
                            address: remote_address,
                            scope: enum_from_value(&scope).unwrap_or(AddressScope::Reserved),
                            country: row.get(8)?,
                            region: row.get(9)?,
                            city_approximate: row.get(10)?,
                            asn: row.get(11)?,
                            organization: row.get(12)?,
                            database_version: row.get(13)?,
                            enriched_at: row.get(14)?,
                        },
                        interface: row.get(4)?,
                        packets: row.get::<_, i64>(17)? as u64,
                        bytes: row.get::<_, i64>(18)? as u64,
                        inbound_bps: 0,
                        outbound_bps: 0,
                        traffic: DirectionTotalsDto {
                            inbound: CountersDto {
                                packets: row.get::<_, i64>(19)? as u64,
                                bytes: row.get::<_, i64>(20)? as u64,
                            },
                            outbound: CountersDto {
                                packets: row.get::<_, i64>(21)? as u64,
                                bytes: row.get::<_, i64>(22)? as u64,
                            },
                        },
                        first_seen: row.get(25)?,
                        last_seen: row.get(26)?,
                        duration_ms: row.get::<_, i64>(27)?.max(0) as u64,
                        domains: Vec::new(),
                    },
                    row.get::<_, String>(30)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut items = Vec::with_capacity(rows.len());
        for (mut connection, domains_json) in rows {
            let groups: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
            let mut domains: Vec<DomainRefDto> = Vec::new();
            for group in &groups {
                let associations: Vec<DomainRefDto> =
                    serde_json::from_str(group).unwrap_or_default();
                for association in &associations {
                    push_domain(&mut domains, association);
                }
            }
            domains.sort_by(|left, right| left.domain.cmp(&right.domain));
            connection.domains = domains;
            if connection.service.is_none() {
                // Historical rows predate fingerprinting: Domain Evidence from
                // a parsed TLS/HTTP handshake still names the protocol.
                connection.service = evidence_service(&connection.domains).map(ToOwned::to_owned);
            }
            if let Some(rate) = self.rates_by_connection.get(&connection.id) {
                connection.inbound_bps = rate.inbound_bps();
                connection.outbound_bps = rate.outbound_bps();
            }
            items.push(connection);
        }

        Ok(Page {
            items,
            total: total as usize,
            limit,
            offset,
        })
    }

    fn flows_page(
        &self,
        query: &FlowQuery,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<FlowDto>, usize), ApiError> {
        let now = SystemTime::now();
        let total = self.count_flows(query, now)?;
        let (clauses, params) = self.flow_clauses(query, now, "", true)?;
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
        let mut items = statement
            .query_map(params_from_iter(params), flow_dto_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_flow_rate(item);
        }
        Ok((items, total))
    }

    fn count_flows(&self, query: &FlowQuery, now: SystemTime) -> Result<usize, ApiError> {
        let (clauses, params) = self.flow_clauses(query, now, "", true)?;
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
        let (clauses, params) = self.flow_clauses(query, now, "", true)?;
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
            "SELECT remote_addr, MAX(remote_scope), MAX(remote_country) AS country, \
             MAX(remote_region), MAX(remote_asn) AS asn, MAX(remote_org) AS organization, \
             SUM(packets) AS total_packets, SUM(bytes) AS total_bytes, \
             COALESCE(SUM(CASE WHEN direction = 'inbound' THEN packets ELSE 0 END), 0) AS in_packets, \
             COALESCE(SUM(CASE WHEN direction = 'inbound' THEN bytes ELSE 0 END), 0) AS in_bytes, \
             COALESCE(SUM(CASE WHEN direction = 'outbound' THEN packets ELSE 0 END), 0) AS out_packets, \
             COALESCE(SUM(CASE WHEN direction = 'outbound' THEN bytes ELSE 0 END), 0) AS out_bytes, \
             COUNT(*), MIN(first_seen_ms), MAX(last_seen_ms) \
             FROM flows {where_clause} GROUP BY remote_addr ORDER BY {order} \
             LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        let mut params = params;
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let mut items = statement
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
                    inbound_bps: 0,
                    outbound_bps: 0,
                    traffic: DirectionTotalsDto {
                        inbound: CountersDto {
                            packets: row.get::<_, i64>(8)? as u64,
                            bytes: row.get::<_, i64>(9)? as u64,
                        },
                        outbound: CountersDto {
                            packets: row.get::<_, i64>(10)? as u64,
                            bytes: row.get::<_, i64>(11)? as u64,
                        },
                    },
                    flow_count: row.get::<_, i64>(12)? as u64,
                    first_seen: row.get(13)?,
                    last_seen: row.get(14)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_endpoint_rate(item);
        }
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

        let mut addresses_statement = self.conn.prepare(
            "SELECT f.remote_addr, MAX(f.remote_country), MAX(f.remote_asn), MAX(f.remote_org), \
             COALESCE(SUM(f.bytes), 0), COALESCE(MIN(f.first_seen_ms), 0), \
             COALESCE(MAX(f.last_seen_ms), 0), \
             GROUP_CONCAT(DISTINCT je.value->>'evidence'), \
             MAX(CASE WHEN je.value->>'confidence' = 'direct' THEN 1 ELSE 0 END) \
             FROM flows f, json_each(f.domains_json) je WHERE je.value->>'domain' = ?1 \
             GROUP BY f.remote_addr ORDER BY 5 DESC, f.remote_addr",
        )?;
        let addresses = addresses_statement
            .query_map([&domain], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<u32>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(
                |(
                    address,
                    country,
                    asn,
                    organization,
                    bytes,
                    first_seen,
                    last_seen,
                    evidence,
                    direct,
                )| {
                    // Addresses come from the persisted Flow association, not
                    // from the expiring observation table, so a domain keeps
                    // its address history after the observation rows age out.
                    DomainAddressDto {
                        address,
                        evidence: split_enum_list(evidence.as_deref().unwrap_or("")),
                        confidence: if direct != 0 {
                            AssociationConfidence::Direct
                        } else {
                            AssociationConfidence::Inferred
                        },
                        country,
                        asn,
                        organization,
                        bytes: bytes as u64,
                        first_seen,
                        last_seen,
                    }
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
        let (mut clauses, mut params) = self.flow_clauses(query, now, "flows.", false)?;
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
             SUM(flows.bytes) AS total_bytes, \
             COALESCE(SUM(CASE WHEN flows.direction = 'inbound' THEN flows.packets ELSE 0 END), 0) \
                 AS in_packets, \
             COALESCE(SUM(CASE WHEN flows.direction = 'inbound' THEN flows.bytes ELSE 0 END), 0) \
                 AS in_bytes, \
             COALESCE(SUM(CASE WHEN flows.direction = 'outbound' THEN flows.packets ELSE 0 END), 0) \
                 AS out_packets, \
             COALESCE(SUM(CASE WHEN flows.direction = 'outbound' THEN flows.bytes ELSE 0 END), 0) \
                 AS out_bytes, \
             COUNT(*) AS flow_count, MIN(flows.first_seen_ms), MAX(flows.last_seen_ms), \
             GROUP_CONCAT(DISTINCT je.value->>'evidence') AS evidences \
             FROM flows, json_each(flows.domains_json) je {where_clause} GROUP BY 1 \
             ORDER BY {order} LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Value::Integer(limit as i64));
        params.push(Value::Integer(offset as i64));

        let mut statement = self.conn.prepare(&sql)?;
        let mut items = statement
            .query_map(params_from_iter(params), |row| {
                Ok(DomainSummaryDto {
                    domain: row.get(0)?,
                    packets: row.get::<_, i64>(1)? as u64,
                    bytes: row.get::<_, i64>(2)? as u64,
                    inbound_bps: 0,
                    outbound_bps: 0,
                    traffic: DirectionTotalsDto {
                        inbound: CountersDto {
                            packets: row.get::<_, i64>(3)? as u64,
                            bytes: row.get::<_, i64>(4)? as u64,
                        },
                        outbound: CountersDto {
                            packets: row.get::<_, i64>(5)? as u64,
                            bytes: row.get::<_, i64>(6)? as u64,
                        },
                    },
                    flow_count: row.get::<_, i64>(7)? as u64,
                    first_seen: row.get(8)?,
                    last_seen: row.get(9)?,
                    evidence: split_enum_list(&row.get::<_, String>(10)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_domain_rate(item);
        }
        Ok((items, total as usize))
    }

    // ------------------------------------------------------- tick aggregates

    /// Refreshed endpoint summaries for the given remote addresses, used by
    /// the SSE tick so Endpoint lists update without polling.
    fn endpoint_summaries_for(
        &self,
        addresses: &HashSet<String>,
    ) -> Result<Vec<EndpointSummaryDto>, ApiError> {
        if addresses.is_empty() {
            return Ok(Vec::new());
        }
        let keys = json_key_list(addresses.iter())?;
        let mut statement = self.conn.prepare(
            "SELECT remote_addr, MAX(remote_scope), MAX(remote_country) AS country, \
             MAX(remote_region), MAX(remote_asn) AS asn, MAX(remote_org) AS organization, \
             SUM(packets) AS total_packets, SUM(bytes) AS total_bytes, \
             COALESCE(SUM(CASE WHEN direction = 'inbound' THEN packets ELSE 0 END), 0) AS in_packets, \
             COALESCE(SUM(CASE WHEN direction = 'inbound' THEN bytes ELSE 0 END), 0) AS in_bytes, \
             COALESCE(SUM(CASE WHEN direction = 'outbound' THEN packets ELSE 0 END), 0) AS out_packets, \
             COALESCE(SUM(CASE WHEN direction = 'outbound' THEN bytes ELSE 0 END), 0) AS out_bytes, \
             COUNT(*), MIN(first_seen_ms), MAX(last_seen_ms) \
             FROM flows WHERE remote_addr IN (SELECT value FROM json_each(?1)) \
             GROUP BY remote_addr ORDER BY total_bytes DESC, remote_addr LIMIT ?2",
        )?;
        let mut items = statement
            .query_map(params![keys, TICK_AGGREGATE_LIMIT as i64], |row| {
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
                    inbound_bps: 0,
                    outbound_bps: 0,
                    traffic: DirectionTotalsDto {
                        inbound: CountersDto {
                            packets: row.get::<_, i64>(8)? as u64,
                            bytes: row.get::<_, i64>(9)? as u64,
                        },
                        outbound: CountersDto {
                            packets: row.get::<_, i64>(10)? as u64,
                            bytes: row.get::<_, i64>(11)? as u64,
                        },
                    },
                    flow_count: row.get::<_, i64>(12)? as u64,
                    first_seen: row.get(13)?,
                    last_seen: row.get(14)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_endpoint_rate(item);
        }
        Ok(items)
    }

    /// Refreshed Associated Domain summaries for the given domains, used by
    /// the SSE tick so Domain lists update without polling.
    fn domain_summaries_for(
        &self,
        domains: &HashSet<String>,
    ) -> Result<Vec<DomainSummaryDto>, ApiError> {
        if domains.is_empty() {
            return Ok(Vec::new());
        }
        let keys = json_key_list(domains.iter())?;
        let mut statement = self.conn.prepare(
            "SELECT je.value->>'domain' AS domain, SUM(flows.packets) AS total_packets, \
             SUM(flows.bytes) AS total_bytes, \
             COALESCE(SUM(CASE WHEN flows.direction = 'inbound' THEN flows.packets ELSE 0 END), 0) \
                 AS in_packets, \
             COALESCE(SUM(CASE WHEN flows.direction = 'inbound' THEN flows.bytes ELSE 0 END), 0) \
                 AS in_bytes, \
             COALESCE(SUM(CASE WHEN flows.direction = 'outbound' THEN flows.packets ELSE 0 END), 0) \
                 AS out_packets, \
             COALESCE(SUM(CASE WHEN flows.direction = 'outbound' THEN flows.bytes ELSE 0 END), 0) \
                 AS out_bytes, \
             COUNT(*) AS flow_count, MIN(flows.first_seen_ms), MAX(flows.last_seen_ms), \
             GROUP_CONCAT(DISTINCT je.value->>'evidence') \
             FROM flows, json_each(flows.domains_json) je \
             WHERE je.value->>'domain' IN (SELECT value FROM json_each(?1)) \
             GROUP BY 1 ORDER BY total_bytes DESC, domain LIMIT ?2",
        )?;
        let mut items = statement
            .query_map(params![keys, TICK_AGGREGATE_LIMIT as i64], |row| {
                Ok(DomainSummaryDto {
                    domain: row.get(0)?,
                    packets: row.get::<_, i64>(1)? as u64,
                    bytes: row.get::<_, i64>(2)? as u64,
                    inbound_bps: 0,
                    outbound_bps: 0,
                    traffic: DirectionTotalsDto {
                        inbound: CountersDto {
                            packets: row.get::<_, i64>(3)? as u64,
                            bytes: row.get::<_, i64>(4)? as u64,
                        },
                        outbound: CountersDto {
                            packets: row.get::<_, i64>(5)? as u64,
                            bytes: row.get::<_, i64>(6)? as u64,
                        },
                    },
                    flow_count: row.get::<_, i64>(7)? as u64,
                    first_seen: row.get(8)?,
                    last_seen: row.get(9)?,
                    evidence: split_enum_list(&row.get::<_, String>(10)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for item in &mut items {
            self.apply_domain_rate(item);
        }
        Ok(items)
    }

    /// Live counters over the whole retained history.
    fn tick_overview(&mut self) -> Result<TickOverviewDto, ApiError> {
        let now = Instant::now();
        if let Some((cached_at, cached)) = self.overview_cache {
            if now.saturating_duration_since(cached_at) < OVERVIEW_CACHE_TTL {
                return Ok(cached);
            }
        }

        let (flows_total, flows_with_domain, active_flows): (i64, i64, i64) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(domains_json <> '[]'), 0), \
                 COALESCE(SUM(state = 'active'), 0) FROM flows",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let ratio = if flows_total == 0 {
            0.0
        } else {
            flows_with_domain as f64 / flows_total as f64
        };
        let overview = TickOverviewDto {
            active_flows: active_flows as u64,
            flows_total: flows_total as u64,
            flows_with_domain: flows_with_domain as u64,
            ratio,
        };
        self.overview_cache = Some((now, overview));
        Ok(overview)
    }

    // --------------------------------------------------------------- overview

    pub(crate) fn overview(
        &self,
        range: TimeRange,
        exclude_scope: &[AddressScope],
        now: SystemTime,
    ) -> Result<OverviewDto, ApiError> {
        let query = FlowQuery {
            range: Some(range),
            limit: Some(TOP_LIST_LIMIT),
            exclude_scope: exclude_scope.to_vec(),
            ..FlowQuery::default()
        };
        let (clauses, params) = self.flow_clauses(&query, now, "", true)?;
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
        let by_evidence = self.aggregate_evidence(&query, now)?;
        let proxied = self.aggregate_proxied(&query, now)?;

        Ok(OverviewDto {
            range: range.as_str(),
            generated_at: unix_millis(now),
            rates: if self.rates_are_fresh(now) {
                RateDto {
                    inbound_bps: self.rates.inbound_bps(),
                    outbound_bps: self.rates.outbound_bps(),
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
                by_evidence,
            },
            proxied,
            health: self.health.as_ref().map(CollectorHealthDto::from_health),
        })
    }

    /// Fake-IP traffic totals: present at the boundary, but terminated by the
    /// local proxy, so geography cannot be attributed.
    fn aggregate_proxied(
        &self,
        query: &FlowQuery,
        now: SystemTime,
    ) -> Result<ProxiedTrafficDto, ApiError> {
        let (mut clauses, params) = self.flow_clauses(query, now, "", true)?;
        clauses.push("remote_scope = 'fake_ip'".to_owned());
        let sql = format!(
            "SELECT COUNT(*), COALESCE(SUM(bytes), 0), \
             COALESCE(SUM(domains_json <> '[]'), 0), \
             COALESCE(SUM(remote_country IS NOT NULL), 0) FROM flows {}",
            where_sql(&clauses)
        );
        let (flows, bytes, flows_with_domain, resolved_flows): (i64, i64, i64, i64) =
            self.conn.query_row(&sql, params_from_iter(params), |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?;
        Ok(ProxiedTrafficDto {
            flows: flows as u64,
            bytes: bytes as u64,
            flows_with_domain: flows_with_domain as u64,
            resolved_flows: resolved_flows as u64,
        })
    }

    /// Flow counts per Domain Evidence inside the overview range.
    fn aggregate_evidence(
        &self,
        query: &FlowQuery,
        now: SystemTime,
    ) -> Result<Vec<EvidenceCountDto>, ApiError> {
        let (mut clauses, params) = self.flow_clauses(query, now, "flows.", true)?;
        clauses.push("je.value->>'evidence' IS NOT NULL".to_owned());
        let sql = format!(
            "SELECT je.value->>'evidence', COUNT(DISTINCT flows.id) FROM flows, \
             json_each(flows.domains_json) je {} GROUP BY 1 ORDER BY 2 DESC",
            where_sql(&clauses)
        );
        let mut statement = self.conn.prepare(&sql)?;
        let items = statement
            .query_map(params_from_iter(params), |row| {
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
        Ok(items)
    }

    fn aggregate_countries(
        &self,
        query: &FlowQuery,
        now: SystemTime,
    ) -> Result<Vec<CountryCountDto>, ApiError> {
        let (mut clauses, params) = self.flow_clauses(query, now, "", true)?;
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
        let (mut clauses, params) = self.flow_clauses(query, now, "", true)?;
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
        self.buckets_timeline(range, now, None)
    }

    /// Boundary traffic timeline for one Endpoint (remote address).
    pub(crate) fn endpoint_timeline(
        &self,
        address: &str,
        range: TimeRange,
        now: SystemTime,
    ) -> Result<TimelineDto, ApiError> {
        let address: IpAddr = address
            .parse()
            .map_err(|_| ApiError::bad_request(format!("invalid IP address: {address}")))?;
        self.buckets_timeline(range, now, Some(("endpoint", &address.to_string())))
    }

    /// Boundary traffic timeline for one Associated Domain.
    pub(crate) fn domain_timeline(
        &self,
        domain: &str,
        range: TimeRange,
        now: SystemTime,
    ) -> Result<TimelineDto, ApiError> {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return Err(ApiError::bad_request("domain must not be empty"));
        }
        self.buckets_timeline(range, now, Some(("domain", &domain)))
    }

    fn buckets_timeline(
        &self,
        range: TimeRange,
        now: SystemTime,
        entity: Option<(&str, &str)>,
    ) -> Result<TimelineDto, ApiError> {
        let (resolution, step_ms) = match range {
            TimeRange::Minute15 | TimeRange::Hour1 => ("minute", 60_000i64),
            TimeRange::Hour24 | TimeRange::Day7 => ("hour", 3_600_000i64),
        };
        let end = unix_millis(now).div_euclid(step_ms) * step_ms;
        let start = unix_millis(range.cutoff(now)).div_euclid(step_ms) * step_ms;

        let mut sql =
            String::from("SELECT start_ms, in_packets, in_bytes, out_packets, out_bytes FROM ");
        let mut params = vec![
            Value::Text(resolution.to_owned()),
            Value::Integer(start),
            Value::Integer(end),
        ];
        match entity {
            Some((kind, key)) => {
                sql.push_str(
                    "entity_buckets WHERE resolution = ?1 AND start_ms BETWEEN ?2 AND ?3 \
                     AND kind = ?4 AND key = ?5 ORDER BY start_ms",
                );
                params.push(Value::Text(kind.to_owned()));
                params.push(Value::Text(key.to_owned()));
            }
            None => {
                sql.push_str(
                    "traffic_buckets WHERE resolution = ?1 AND start_ms BETWEEN ?2 AND ?3 \
                     ORDER BY start_ms",
                );
            }
        }

        let mut points: HashMap<i64, TimelinePointDto> = HashMap::new();
        let mut statement = self.conn.prepare(&sql)?;
        for row in statement.query_map(params_from_iter(params), |row| {
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
        let (clauses, mut params) = self.flow_clauses(query, now, "", true)?;
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
                 DELETE FROM entity_buckets; DELETE FROM entity_rates; \
                 DELETE FROM applications; DELETE FROM exports;",
            )?;
            Ok(())
        })();
        if let Err(error) = result {
            self.database_error = Some(error.to_string());
        }
        self.rates = EntityRates::default();
        self.rates_by_flow.clear();
        self.rates_by_connection.clear();
        self.rates_by_endpoint.clear();
        self.rates_by_domain.clear();
        self.rates_by_application.clear();
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

    // ----------------------------------------------------------- traffic rules

    /// Monotonic token that advances on every Traffic Rule mutation.
    pub(crate) fn rules_revision(&self) -> u64 {
        self.rules_revision
    }

    pub(crate) fn list_traffic_rules(&self) -> Result<Vec<TrafficRuleRecord>, ApiError> {
        let mut statement = self.conn.prepare(
            "SELECT id, action, direction, selector_json, rate_bytes_per_s, burst_bytes, \
             enabled, created_at_ms, updated_at_ms FROM traffic_rules ORDER BY id",
        )?;
        let rows = statement
            .query_map([], traffic_rule_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(RawTrafficRule::into_record).collect()
    }

    pub(crate) fn traffic_rule(&self, id: i64) -> Result<TrafficRuleRecord, ApiError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, action, direction, selector_json, rate_bytes_per_s, burst_bytes, \
                 enabled, created_at_ms, updated_at_ms FROM traffic_rules WHERE id = ?1",
                [id],
                traffic_rule_row,
            )
            .optional()?;
        match row {
            Some(row) => row.into_record(),
            None => Err(ApiError::not_found(format!("traffic rule {id}"))),
        }
    }

    pub(crate) fn insert_traffic_rule(
        &mut self,
        draft: &TrafficRuleDraft,
    ) -> Result<TrafficRuleRecord, ApiError> {
        let selector = selector_json(&draft.selector)?;
        let (rate, burst) = draft.action.rates();
        let now = unix_millis(SystemTime::now());
        self.conn.execute(
            "INSERT INTO traffic_rules (action, direction, selector_json, rate_bytes_per_s, \
             burst_bytes, enabled, created_at_ms, updated_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                action_name(draft.action.action()),
                draft.direction.as_str(),
                selector,
                rate as i64,
                burst as i64,
                i64::from(draft.enabled),
                now,
            ],
        )?;
        self.rules_revision += 1;
        self.traffic_rule(self.conn.last_insert_rowid())
    }

    pub(crate) fn update_traffic_rule(
        &mut self,
        id: i64,
        draft: &TrafficRuleDraft,
    ) -> Result<TrafficRuleRecord, ApiError> {
        let selector = selector_json(&draft.selector)?;
        let (rate, burst) = draft.action.rates();
        let now = unix_millis(SystemTime::now());
        let changed = self.conn.execute(
            "UPDATE traffic_rules SET action = ?1, direction = ?2, selector_json = ?3, \
             rate_bytes_per_s = ?4, burst_bytes = ?5, enabled = ?6, updated_at_ms = ?7 \
             WHERE id = ?8",
            params![
                action_name(draft.action.action()),
                draft.direction.as_str(),
                selector,
                rate as i64,
                burst as i64,
                i64::from(draft.enabled),
                now,
                id,
            ],
        )?;
        if changed == 0 {
            return Err(ApiError::not_found(format!("traffic rule {id}")));
        }
        self.rules_revision += 1;
        self.traffic_rule(id)
    }

    pub(crate) fn delete_traffic_rule(&mut self, id: i64) -> Result<(), ApiError> {
        let changed = self
            .conn
            .execute("DELETE FROM traffic_rules WHERE id = ?1", [id])?;
        if changed == 0 {
            return Err(ApiError::not_found(format!("traffic rule {id}")));
        }
        self.rules_revision += 1;
        Ok(())
    }

    /// Stored process name for an Application Identity, when one exists.
    ///
    /// `proc:<exe>` rules compile to the `comm` the kernel records, so the
    /// API resolves the executable path through this lookup.
    pub(crate) fn application_comm(&self, id: &str) -> Option<String> {
        self.conn
            .query_row("SELECT comm FROM applications WHERE id = ?1", [id], |row| {
                row.get::<_, Option<String>>(0)
            })
            .optional()
            .ok()
            .flatten()
            .flatten()
            .filter(|comm| !comm.is_empty())
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

    /// Records one local operation in the audit ring (PRD 8.10).
    pub(crate) fn record_operation(&mut self, action: &'static str, outcome: &'static str) {
        self.audit(action, outcome);
    }

    pub(crate) fn enrichment_status(&self) -> (EnrichmentStats, Option<String>) {
        (self.enricher.stats(), self.enrichment_error.clone())
    }

    /// Enriches stored public addresses that were not covered by the current
    /// GeoIP database. Idempotent: rows already carrying the active database
    /// version are skipped, so a later database swap refreshes them on the
    /// next start while restarts with the same file do nothing.
    pub(crate) fn backfill_enrichment(&mut self) -> Result<usize, ApiError> {
        let Some(version) = self.enricher.stats().database_version else {
            return Ok(0);
        };
        let addresses = {
            let mut statement = self.conn.prepare(
                "SELECT DISTINCT remote_addr FROM flows WHERE remote_scope = 'public' \
                 AND (remote_db_version IS NULL OR remote_db_version != ?1)",
            )?;
            statement
                .query_map([version.as_ref()], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
        };

        let mut updated = 0;
        for address in addresses {
            let Ok(address) = address.parse::<IpAddr>() else {
                continue;
            };
            let profile = self.enricher.profile(address);
            if profile.country.is_none() && profile.asn.is_none() && profile.organization.is_none()
            {
                continue;
            }
            updated += self.conn.execute(
                "UPDATE flows SET remote_country = ?1, remote_region = ?2, remote_city = ?3, \
                 remote_asn = ?4, remote_org = ?5, remote_db_version = ?6, \
                 remote_enriched_at_ms = ?7 \
                 WHERE remote_addr = ?8 AND remote_scope = 'public'",
                params![
                    profile.country.as_deref(),
                    profile.region.as_deref(),
                    profile.city_approximate.as_deref(),
                    profile.asn.map(i64::from),
                    profile.organization.as_deref(),
                    profile.database_version.as_deref(),
                    unix_millis(profile.enriched_at),
                    address.to_string(),
                ],
            )?;
        }
        Ok(updated)
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
    ) -> Result<(Vec<String>, Vec<Value>), ApiError> {
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
                 ' ' || coalesce({prefix}app_id, '') || ' ' || coalesce({prefix}service, '') || \
                 ' ' || {prefix}domains_json), ?) > 0"
            ));
            params.push(Value::Text(q));
        }
        match (query.start, query.end) {
            (Some(start), Some(end)) => {
                if query.range.is_some() {
                    return Err(ApiError::unprocessable(
                        "range and start/end are mutually exclusive",
                    ));
                }
                if start > end {
                    return Err(ApiError::unprocessable("start must not be after end"));
                }
                clauses.push(format!(
                    "({prefix}last_seen_ms >= ? AND {prefix}last_seen_ms <= ?)"
                ));
                params.push(Value::Integer(start));
                params.push(Value::Integer(end));
            }
            (None, None) => {
                if let Some(range) = query.range {
                    clauses.push(format!("{prefix}last_seen_ms >= ?"));
                    params.push(Value::Integer(unix_millis(range.cutoff(now))));
                }
            }
            _ => {
                return Err(ApiError::unprocessable(
                    "start and end must be provided together",
                ));
            }
        }
        if let Some(direction) = query.direction {
            clauses.push(format!("{prefix}direction = ?"));
            params.push(Value::Text(enum_value(direction)));
        }
        if let Some(protocol) = query.protocol {
            clauses.push(format!("{prefix}protocol = ?"));
            params.push(Value::Text(enum_value(protocol)));
        }
        if let Some(service) = query
            .service
            .as_deref()
            .map(str::trim)
            .filter(|service| !service.is_empty())
        {
            clauses.push(format!("{prefix}service = ? COLLATE NOCASE"));
            params.push(Value::Text(service.to_owned()));
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
        if let Some(application_id) = &query.application_id {
            clauses.push(format!("{prefix}app_id = ?"));
            params.push(Value::Text(application_id.clone()));
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
        if !query.scope.is_empty() {
            let placeholders = vec!["?"; query.scope.len()].join(", ");
            clauses.push(format!("{prefix}remote_scope IN ({placeholders})"));
            for scope in &query.scope {
                params.push(Value::Text(enum_value(*scope)));
            }
        }
        if !query.exclude_scope.is_empty() {
            let placeholders = vec!["?"; query.exclude_scope.len()].join(", ");
            clauses.push(format!("{prefix}remote_scope NOT IN ({placeholders})"));
            for scope in &query.exclude_scope {
                params.push(Value::Text(enum_value(*scope)));
            }
        }
        if let Some(state) = query.state {
            clauses.push(format!("{prefix}state = ?"));
            params.push(Value::Text(state.as_str().to_owned()));
        }
        if let Some(has_domain) = query.has_domain {
            clauses.push(format!("({prefix}domains_json <> '[]') = ?"));
            params.push(Value::Integer(i64::from(has_domain)));
        }

        Ok((clauses, params))
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

/// Collaborators shared by every upsert of one collection interval.
struct FlowWriter<'a> {
    enricher: &'a mut Enricher,
    applications: &'a mut ApplicationResolver,
    interfaces: &'a HashMap<u32, Box<str>>,
    proxy: &'a ProxyResolver,
}

fn upsert_flow(
    tx: &rusqlite::Transaction<'_>,
    id: u64,
    update: &FlowUpdate,
    now_instant: Instant,
    now_system: SystemTime,
    writer: &mut FlowWriter<'_>,
) -> Result<(), ApiError> {
    let remote = remote_endpoint(&update.key);
    let profile = resolved_profile(update, remote, writer.enricher, writer.proxy);
    let domains_json = associate_address(tx, remote.address, now_system)?;
    let first_seen = instant_to_system(update.first_seen, now_instant, now_system);
    let last_seen = instant_to_system(update.last_seen, now_instant, now_system);
    let end_reason = match update.state {
        FlowState::Ended(reason) => Some(enum_value(reason)),
        FlowState::Active => None,
    };
    let interface = writer.interfaces.get(&update.key.interface_index.get());
    let application = writer.applications.resolve(update.application.as_ref());
    if let Some(application) = &application {
        upsert_application(tx, application, first_seen, last_seen)?;
    }

    tx.execute(
        "INSERT INTO flows (id, direction, protocol, src_addr, src_port, dst_addr, dst_port, \
         ifindex, interface, packets, bytes, first_seen_ms, last_seen_ms, state, end_reason, \
         remote_addr, remote_port, remote_scope, remote_country, remote_region, remote_city, \
         remote_asn, remote_org, remote_db_version, remote_enriched_at_ms, domains_json, \
         service, app_id) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
         ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28) \
         ON CONFLICT(id) DO UPDATE SET \
         packets = excluded.packets, bytes = excluded.bytes, \
         first_seen_ms = MIN(flows.first_seen_ms, excluded.first_seen_ms), \
         last_seen_ms = MAX(flows.last_seen_ms, excluded.last_seen_ms), \
         state = excluded.state, end_reason = excluded.end_reason, \
         interface = excluded.interface, domains_json = excluded.domains_json, \
         service = COALESCE(excluded.service, flows.service), \
         app_id = COALESCE(excluded.app_id, flows.app_id), \
         remote_scope = excluded.remote_scope, \
         remote_country = CASE WHEN excluded.remote_scope = 'fake_ip' \
             THEN COALESCE(excluded.remote_country, flows.remote_country) \
             ELSE excluded.remote_country END, \
         remote_region = CASE WHEN excluded.remote_scope = 'fake_ip' \
             THEN COALESCE(excluded.remote_region, flows.remote_region) \
             ELSE excluded.remote_region END, \
         remote_city = CASE WHEN excluded.remote_scope = 'fake_ip' \
             THEN COALESCE(excluded.remote_city, flows.remote_city) \
             ELSE excluded.remote_city END, \
         remote_asn = CASE WHEN excluded.remote_scope = 'fake_ip' \
             THEN COALESCE(excluded.remote_asn, flows.remote_asn) \
             ELSE excluded.remote_asn END, \
         remote_org = CASE WHEN excluded.remote_scope = 'fake_ip' \
             THEN COALESCE(excluded.remote_org, flows.remote_org) \
             ELSE excluded.remote_org END, \
         remote_db_version = CASE WHEN excluded.remote_scope = 'fake_ip' \
             THEN COALESCE(excluded.remote_db_version, flows.remote_db_version) \
             ELSE excluded.remote_db_version END, \
         remote_enriched_at_ms = CASE WHEN excluded.remote_scope = 'fake_ip' \
             AND excluded.remote_country IS NULL AND excluded.remote_asn IS NULL \
             AND excluded.remote_db_version IS NULL \
             THEN flows.remote_enriched_at_ms \
             ELSE excluded.remote_enriched_at_ms END",
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
            update.service.as_deref(),
            application
                .as_ref()
                .map(|application| application.id.as_str()),
        ],
    )?;
    Ok(())
}

/// Inserts or refreshes one Application row.
///
/// `kind` and `name` follow the latest observation (a container name may be
/// upgraded later), while the first/last timestamps keep history.
fn upsert_application(
    tx: &rusqlite::Transaction<'_>,
    application: &ResolvedApplication,
    first_seen: SystemTime,
    last_seen: SystemTime,
) -> Result<(), ApiError> {
    tx.execute(
        "INSERT INTO applications (id, kind, name, exe, comm, uid, container_id, first_seen_ms, \
         last_seen_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) \
         ON CONFLICT(id) DO UPDATE SET \
         kind = excluded.kind, name = excluded.name, \
         exe = COALESCE(excluded.exe, applications.exe), \
         comm = COALESCE(excluded.comm, applications.comm), \
         uid = excluded.uid, \
         container_id = COALESCE(excluded.container_id, applications.container_id), \
         first_seen_ms = MIN(applications.first_seen_ms, excluded.first_seen_ms), \
         last_seen_ms = MAX(applications.last_seen_ms, excluded.last_seen_ms)",
        params![
            application.id.as_str(),
            application.kind,
            application.name.as_str(),
            application.exe.as_deref(),
            application.comm.as_str(),
            application.uid as i64,
            application.container_id.as_deref(),
            unix_millis(first_seen),
            unix_millis(last_seen),
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

/// Adds one Flow delta to an entity (Endpoint or Domain) time bucket.
fn add_entity_bucket(
    tx: &rusqlite::Transaction<'_>,
    kind: &str,
    key: &str,
    resolution: &str,
    start: SystemTime,
    direction: FlowDirection,
    delta: TrafficCounters,
) -> Result<(), ApiError> {
    let (in_packets, in_bytes, out_packets, out_bytes) = match direction {
        FlowDirection::Inbound => (delta.packets as i64, delta.bytes as i64, 0, 0),
        FlowDirection::Outbound => (0, 0, delta.packets as i64, delta.bytes as i64),
    };
    tx.execute(
        "INSERT INTO entity_buckets (kind, key, resolution, start_ms, in_packets, in_bytes, \
         out_packets, out_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT(kind, key, resolution, start_ms) DO UPDATE SET \
         in_packets = entity_buckets.in_packets + excluded.in_packets, \
         in_bytes = entity_buckets.in_bytes + excluded.in_bytes, \
         out_packets = entity_buckets.out_packets + excluded.out_packets, \
         out_bytes = entity_buckets.out_bytes + excluded.out_bytes",
        params![
            kind,
            key,
            resolution,
            unix_millis(start),
            in_packets,
            in_bytes,
            out_packets,
            out_bytes,
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
        inbound_bps: 0,
        outbound_bps: 0,
        first_seen,
        last_seen,
        duration_ms: (last_seen - first_seen).max(0) as u64,
        domains: serde_json::from_str(&domains_json).unwrap_or_default(),
        application: flow_application_from_row(row)?,
    })
}

fn flow_application_from_row(row: &Row<'_>) -> rusqlite::Result<Option<ApplicationRefDto>> {
    let Some(id) = row.get::<_, Option<String>>(27)? else {
        return Ok(None);
    };
    Ok(Some(ApplicationRefDto {
        id,
        name: row.get::<_, Option<String>>(28)?.unwrap_or_default(),
        kind: match row.get::<_, Option<String>>(29)?.as_deref() {
            Some("container") => "container",
            _ => "process",
        },
    }))
}

fn application_summary_from_row(row: &Row<'_>) -> rusqlite::Result<ApplicationSummaryDto> {
    let id: String = row.get(0)?;
    let name: Option<String> = row.get(1)?;
    Ok(ApplicationSummaryDto {
        name: name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| id.clone()),
        id,
        kind: match row.get::<_, Option<String>>(2)?.as_deref() {
            Some("container") => "container",
            _ => "process",
        },
        exe: row.get(3)?,
        comm: row.get(4)?,
        uid: row.get::<_, Option<i64>>(5)?.map(|uid| uid as u32),
        container_id: row.get(6)?,
        packets: row.get::<_, i64>(7)? as u64,
        bytes: row.get::<_, i64>(8)? as u64,
        inbound_bps: 0,
        outbound_bps: 0,
        traffic: DirectionTotalsDto {
            inbound: CountersDto {
                packets: row.get::<_, i64>(9)? as u64,
                bytes: row.get::<_, i64>(10)? as u64,
            },
            outbound: CountersDto {
                packets: row.get::<_, i64>(11)? as u64,
                bytes: row.get::<_, i64>(12)? as u64,
            },
        },
        flow_count: row.get::<_, i64>(13)? as u64,
        first_seen: row.get(14)?,
        last_seen: row.get(15)?,
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
         remote_port,interface,packets,bytes,first_seen_ms,last_seen_ms,domain,evidence,confidence,\
         application\n",
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
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
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
            csv_field(
                flow.application
                    .as_ref()
                    .map(|application| application.id.as_str())
                    .unwrap_or("")
            ),
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
        "last_seen" => "last_seen_ms".to_owned(),
        "first_seen" => "first_seen_ms".to_owned(),
        "bytes" => "bytes".to_owned(),
        "packets" => "packets".to_owned(),
        "direction" => "direction".to_owned(),
        "remote" => "ip_sort_key(remote_addr)".to_owned(),
        "application" => "app_id".to_owned(),
        "domain" => "domain_sort_key(json_extract(domains_json, '$[0].domain'))".to_owned(),
        "rate" | "in_rate" | "out_rate" => rate_order("flow", "CAST(flows.id AS TEXT)", field),
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, id {direction}"))
}

fn application_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-bytes");
    let column = match field {
        "bytes" => "total_bytes".to_owned(),
        "packets" => "total_packets".to_owned(),
        "in_bytes" => "in_bytes".to_owned(),
        "out_bytes" => "out_bytes".to_owned(),
        "flows" => "flow_count".to_owned(),
        "last_seen" => "last_seen_ms".to_owned(),
        "name" => "app_name COLLATE NOCASE".to_owned(),
        "rate" | "in_rate" | "out_rate" => rate_order("application", "flows.app_id", field),
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, app_id {direction}"))
}

fn endpoint_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-bytes");
    let column = match field {
        "bytes" => "total_bytes".to_owned(),
        "packets" => "total_packets".to_owned(),
        "in_bytes" => "in_bytes".to_owned(),
        "out_bytes" => "out_bytes".to_owned(),
        "last_seen" => "last_seen_ms".to_owned(),
        "address" => "ip_sort_key(remote_addr)".to_owned(),
        "country" => "country".to_owned(),
        "organization" => "organization".to_owned(),
        "asn" => "asn".to_owned(),
        "rate" | "in_rate" | "out_rate" => rate_order("endpoint", "remote_addr", field),
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, remote_addr {direction}"))
}

fn domain_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-bytes");
    let column = match field {
        "bytes" => "total_bytes".to_owned(),
        "packets" => "total_packets".to_owned(),
        "in_bytes" => "in_bytes".to_owned(),
        "out_bytes" => "out_bytes".to_owned(),
        "last_seen" => "last_seen_ms".to_owned(),
        "domain" => "domain_sort_key(je.value->>'domain')".to_owned(),
        "evidence" => "evidences".to_owned(),
        "rate" | "in_rate" | "out_rate" => rate_order("domain", "je.value->>'domain'", field),
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!("{column} {direction}, domain {direction}"))
}

fn connection_order(sort: Option<&str>) -> Result<String, ApiError> {
    let (field, descending) = split_sort(sort, "-last_seen");
    let column = match field {
        "last_seen" => "last_seen_ms".to_owned(),
        "first_seen" => "first_seen_ms".to_owned(),
        "duration_ms" => "duration_ms".to_owned(),
        "bytes" => "total_bytes".to_owned(),
        "packets" => "total_packets".to_owned(),
        "in_bytes" => "in_bytes".to_owned(),
        "out_bytes" => "out_bytes".to_owned(),
        "service" => "service".to_owned(),
        "remote" => "ip_sort_key(MAX(remote_addr))".to_owned(),
        "domain" => "domain_sort_key(MIN(json_extract(domains_json, '$[0].domain')))".to_owned(),
        "rate" | "in_rate" | "out_rate" => rate_order(
            "connection",
            "connection_key(protocol, ifindex, pair_lo, pair_hi)",
            field,
        ),
        _ => return Err(unsupported_sort(field)),
    };
    let direction = if descending { "DESC" } else { "ASC" };
    Ok(format!(
        "{column} {direction}, pair_lo {direction}, pair_hi {direction}"
    ))
}

/// Stable derived id for an unordered endpoint pair (FNV-1a 64).
fn connection_id(protocol: Protocol, ifindex: i64, pair_lo: &str, pair_hi: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in enum_value(protocol)
        .bytes()
        .chain(ifindex.to_le_bytes())
        .chain(pair_lo.bytes())
        .chain([0u8])
        .chain(pair_hi.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Canonical unordered endpoint pair of a Flow, matching the `MIN`/`MAX`
/// expressions ([`PAIR_LO`], [`PAIR_HI`]) the connection queries group by.
fn connection_pair(key: &FlowKey) -> (String, String) {
    let side = |endpoint: &Endpoint| match endpoint.port {
        Some(port) => format!("{}:{}", endpoint.address, port),
        None => format!("{}:-1", endpoint.address),
    };
    let source = side(&key.source);
    let destination = side(&key.destination);
    if source <= destination {
        (source, destination)
    } else {
        (destination, source)
    }
}

fn unsupported_sort(field: &str) -> ApiError {
    ApiError::bad_request(format!("unsupported sort field: {field:?}"))
}

/// Rate ordering backed by the latest ingest's `entity_rates` rows.
///
/// `channel` is `rate` (both directions), `in_rate` or `out_rate`. Entities
/// with no rate in the current interval coalesce to zero.
fn rate_order(kind: &str, key: &str, channel: &str) -> String {
    let column = match channel {
        "in_rate" => "inbound_bps",
        "out_rate" => "outbound_bps",
        _ => "inbound_bps + outbound_bps",
    };
    format!(
        "COALESCE((SELECT {column} FROM entity_rates r \
         WHERE r.kind = '{kind}' AND r.key = {key}), 0)"
    )
}

fn where_sql(clauses: &[String]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", clauses.join(" AND "))
    }
}

/// Registers the SQLite scalar helpers used by ordering expressions.
fn register_functions(conn: &Connection) -> Result<(), ApiError> {
    let flags = FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC;
    conn.create_scalar_function("ip_sort_key", 1, flags, |context| {
        let text: Option<String> = context.get(0)?;
        Ok(text.as_deref().and_then(ip_sort_key))
    })?;
    conn.create_scalar_function("domain_sort_key", 1, flags, |context| {
        let text: Option<String> = context.get(0)?;
        Ok(text.as_deref().map(domain_sort_key))
    })?;
    conn.create_scalar_function("connection_key", 4, flags, |context| {
        let protocol: String = context.get(0)?;
        let ifindex: i64 = context.get(1)?;
        let pair_lo: String = context.get(2)?;
        let pair_hi: String = context.get(3)?;
        let Some(protocol) = enum_from_value::<Protocol>(&protocol) else {
            return Ok(None::<String>);
        };
        Ok(Some(connection_id(protocol, ifindex, &pair_lo, &pair_hi)))
    })?;
    Ok(())
}

/// Numeric sort key for an IP address so `2.2.2.2` orders before `10.0.0.1`.
/// IPv6 keys are offset past every IPv4 value.
fn ip_sort_key(text: &str) -> Option<f64> {
    match text.parse::<IpAddr>().ok()? {
        IpAddr::V4(address) => Some(f64::from(u32::from(address))),
        IpAddr::V6(address) => Some(4_294_967_296.0 + (u128::from(address) >> 64) as f64),
    }
}

/// RFC 4034 style canonical key: labels compared from the root up. The
/// separator is below every legal label byte so a shorter name sorts before
/// its own subdomains (`example.com` < `api.example.com`).
fn domain_sort_key(domain: &str) -> String {
    let mut labels: Vec<&str> = domain
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    labels.reverse();
    labels.join("\u{0}")
}

/// Adds a column to an existing table when the schema upgrade needs it.
struct RawTrafficRule {
    id: i64,
    action: String,
    direction: String,
    selector_json: String,
    rate_bytes_per_s: Option<i64>,
    burst_bytes: Option<i64>,
    enabled: i64,
    created_at_ms: i64,
    updated_at_ms: i64,
}

fn traffic_rule_row(row: &Row<'_>) -> rusqlite::Result<RawTrafficRule> {
    Ok(RawTrafficRule {
        id: row.get(0)?,
        action: row.get(1)?,
        direction: row.get(2)?,
        selector_json: row.get(3)?,
        rate_bytes_per_s: row.get(4)?,
        burst_bytes: row.get(5)?,
        enabled: row.get(6)?,
        created_at_ms: row.get(7)?,
        updated_at_ms: row.get(8)?,
    })
}

impl RawTrafficRule {
    fn into_record(self) -> Result<TrafficRuleRecord, ApiError> {
        let action = action_from_name(&self.action).ok_or_else(|| {
            ApiError::internal(format!(
                "traffic rule {} has unknown action {:?}",
                self.id, self.action
            ))
        })?;
        let direction = RuleDirection::from_name(&self.direction).ok_or_else(|| {
            ApiError::internal(format!(
                "traffic rule {} has unknown direction {:?}",
                self.id, self.direction
            ))
        })?;
        let selector: Selector = serde_json::from_str(&self.selector_json).map_err(|error| {
            ApiError::internal(format!(
                "traffic rule {} has an invalid selector: {error}",
                self.id
            ))
        })?;
        let rate = self.rate_bytes_per_s.unwrap_or(0).max(0) as u64;
        let burst = self.burst_bytes.unwrap_or(0).max(0) as u64;
        let action = match action {
            RuleAction::Limit => ActionSpec::Limit {
                rate_bytes_per_s: rate,
                burst_bytes: burst,
            },
            RuleAction::Block => ActionSpec::Block,
        };

        Ok(TrafficRuleRecord {
            rule: TrafficRule {
                id: self.id as u32,
                action,
                direction,
                selector,
                enabled: self.enabled != 0,
            },
            created_at: unix_millis_time(self.created_at_ms),
            updated_at: unix_millis_time(self.updated_at_ms),
        })
    }
}

fn selector_json(selector: &Selector) -> Result<String, ApiError> {
    serde_json::to_string(selector)
        .map_err(|error| ApiError::internal(format!("serialize selector: {error}")))
}

fn unix_millis_time(millis: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(millis.max(0) as u64)
}

impl ApplicationComms for Db {
    fn comm(&self, id: &str) -> Option<String> {
        self.application_comm(id)
    }
}

fn add_column_if_missing(
    conn: &rusqlite::Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), ApiError> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if existing.iter().any(|name| name == column) {
        return Ok(());
    }
    conn.execute_batch(&format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    ))?;
    Ok(())
}

fn split_enum_list(value: &str) -> Vec<DomainEvidence> {
    value
        .split(',')
        .filter_map(|kind| enum_from_value(kind.trim()))
        .collect()
}

/// Sorted, deduplicated JSON array used as a `json_each` key list.
fn json_key_list<'a>(keys: impl Iterator<Item = &'a String>) -> Result<String, ApiError> {
    let mut keys: Vec<&str> = keys.map(String::as_str).collect();
    keys.sort_unstable();
    keys.dedup();
    serde_json::to_string(&keys)
        .map_err(|error| ApiError::internal(format!("serialize aggregate keys: {error}")))
}

/// Overrides a fake-IP profile with the real destination resolved through
/// the proxy control API; keeps demo/GeoIP attribution honest by only using
/// values the proxy itself reported or our own offline GeoIP lookup.
fn resolved_profile(
    update: &FlowUpdate,
    remote: &Endpoint,
    enricher: &mut Enricher,
    proxy: &ProxyResolver,
) -> std::sync::Arc<zimascope_common::model::IpProfile> {
    let profile = enricher.profile(remote.address);
    if profile.scope != AddressScope::FakeIp {
        return profile;
    }
    let (client_address, client_port) = if update.key.source.address == remote.address {
        (update.key.destination.address, update.key.destination.port)
    } else {
        (update.key.source.address, update.key.source.port)
    };
    let Some(key) = ProxyKey::for_fake_flow(client_address, client_port, remote.port) else {
        return profile;
    };
    let Some(resolution) = proxy.lookup(&key) else {
        return profile;
    };

    if let Some(real) = resolution.real_address {
        let real_profile = enricher.profile(real);
        return std::sync::Arc::new(zimascope_common::model::IpProfile {
            address: remote.address,
            scope: profile.scope,
            country: real_profile.country.clone(),
            region: real_profile.region.clone(),
            city_approximate: real_profile.city_approximate.clone(),
            asn: real_profile.asn,
            organization: real_profile.organization.clone(),
            database_version: real_profile.database_version.clone(),
            enriched_at: real_profile.enriched_at,
        });
    }

    if resolution.country.is_some() || resolution.asn.is_some() {
        return std::sync::Arc::new(zimascope_common::model::IpProfile {
            address: remote.address,
            scope: profile.scope,
            country: resolution.country.map(Box::from),
            region: None,
            city_approximate: None,
            asn: resolution.asn,
            organization: None,
            database_version: Some(Box::from("proxy")),
            enriched_at: SystemTime::now(),
        });
    }
    profile
}

/// Names a protocol from parsed TLS/HTTP evidence, for Flows stored before
/// fingerprinting existed.
fn evidence_service(domains: &[DomainRefDto]) -> Option<&'static str> {
    domains
        .iter()
        .find_map(|association| match association.evidence {
            DomainEvidence::TlsSni => Some("TLS"),
            DomainEvidence::HttpHost => Some("HTTP"),
            DomainEvidence::Dns => None,
        })
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
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

    /// Everything except the RFC 3986 unreserved characters.
    const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'_')
        .remove(b'.')
        .remove(b'~');

    utf8_percent_encode(value, URI_COMPONENT).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Db {
        Db::open(&ApiConfig {
            database: None,
            ..ApiConfig::default()
        })
        .expect("open in-memory database")
    }

    fn endpoint_draft() -> TrafficRuleDraft {
        TrafficRuleDraft {
            action: ActionSpec::Limit {
                rate_bytes_per_s: 1_000_000,
                burst_bytes: 1_000_000,
            },
            direction: RuleDirection::Outbound,
            selector: Selector::Endpoint {
                address: "203.0.113.9".parse().expect("address"),
                port: Some(443),
            },
            enabled: true,
        }
    }

    #[test]
    fn traffic_rules_crud_round_trip() {
        let mut db = db();
        assert_eq!(db.rules_revision(), 0);

        let record = db.insert_traffic_rule(&endpoint_draft()).expect("insert");
        assert_eq!(record.rule.id, 1);
        assert_eq!(db.rules_revision(), 1);
        assert_eq!(
            record.rule.selector,
            Selector::Endpoint {
                address: "203.0.113.9".parse().expect("address"),
                port: Some(443),
            }
        );

        assert_eq!(db.list_traffic_rules().expect("list").len(), 1);

        let mut updated = endpoint_draft();
        updated.enabled = false;
        updated.action = ActionSpec::Limit {
            rate_bytes_per_s: 5_000,
            burst_bytes: 5_000,
        };
        let record = db.update_traffic_rule(1, &updated).expect("update");
        assert!(!record.rule.enabled);
        assert_eq!(record.rule.action, updated.action);
        assert_eq!(db.rules_revision(), 2);

        db.delete_traffic_rule(1).expect("delete");
        assert!(db.list_traffic_rules().expect("list").is_empty());
        assert_eq!(db.rules_revision(), 3);
        assert!(db.traffic_rule(1).is_err());
        assert!(db.delete_traffic_rule(1).is_err());
    }

    #[test]
    fn traffic_rules_cover_every_selector_kind() {
        let mut db = db();

        let cidr = db
            .insert_traffic_rule(&TrafficRuleDraft {
                selector: Selector::Cidr {
                    address: "192.0.2.0".parse().expect("address"),
                    prefix_len: 24,
                },
                ..endpoint_draft()
            })
            .expect("insert cidr");
        let application = db
            .insert_traffic_rule(&TrafficRuleDraft {
                selector: Selector::Application {
                    id: "cont:abc".to_owned(),
                },
                action: ActionSpec::Block,
                ..endpoint_draft()
            })
            .expect("insert application");

        assert_eq!(
            cidr.rule.selector,
            Selector::Cidr {
                address: "192.0.2.0".parse().expect("address"),
                prefix_len: 24,
            }
        );
        assert_eq!(
            application.rule.selector,
            Selector::Application {
                id: "cont:abc".to_owned(),
            }
        );
        assert_eq!(application.rule.action, ActionSpec::Block);
    }

    #[test]
    fn migrates_a_v5_database_and_keeps_settings() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("zs-rules-{}-{unique}.db", std::process::id()));
        {
            let conn = Connection::open(&path).expect("open old database");
            conn.execute_batch(
                "CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK (id = 1), \
                 json TEXT NOT NULL, version INTEGER NOT NULL); \
                 INSERT INTO settings VALUES (1, '{\"enabled\":false}', 4); \
                 PRAGMA user_version = 5;",
            )
            .expect("seed old schema");
        }

        let mut db = Db::open(&ApiConfig {
            database: Some(path.clone()),
            ..ApiConfig::default()
        })
        .expect("open upgraded database");
        let (settings, version) = db.load_settings().expect("settings").expect("row");
        assert_eq!(version, 4);
        assert!(!settings.enabled);
        assert!(settings.traffic_rules.enabled);

        let record = db.insert_traffic_rule(&endpoint_draft()).expect("insert");
        assert_eq!(record.rule.id, 1);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn schema_v7_recreates_pre_selector_rule_rows() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("zs-rules-{}-{unique}.db", std::process::id()));
        {
            let conn = Connection::open(&path).expect("open old database");
            conn.execute_batch(
                "CREATE TABLE traffic_rules ( \
                 id INTEGER PRIMARY KEY, action TEXT NOT NULL, direction TEXT NOT NULL, \
                 match_kind TEXT NOT NULL, address TEXT, prefix_len INTEGER, port INTEGER, \
                 application_id TEXT, rate_bytes_per_s INTEGER, burst_bytes INTEGER, \
                 enabled INTEGER NOT NULL, created_at_ms INTEGER NOT NULL, \
                 updated_at_ms INTEGER NOT NULL); \
                 INSERT INTO traffic_rules (action, direction, match_kind, address, port, \
                 rate_bytes_per_s, burst_bytes, enabled, created_at_ms, updated_at_ms) \
                 VALUES ('limit', 'outbound', 'endpoint', '203.0.113.9', 443, \
                 1000000, 1000000, 1, 0, 0); \
                 PRAGMA user_version = 6;",
            )
            .expect("seed v6 schema");
        }

        let mut db = Db::open(&ApiConfig {
            database: Some(path.clone()),
            ..ApiConfig::default()
        })
        .expect("open upgraded database");
        assert!(db.list_traffic_rules().expect("list").is_empty());

        let record = db.insert_traffic_rule(&endpoint_draft()).expect("insert");
        assert_eq!(record.rule.selector, endpoint_draft().selector);

        drop(db);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn uri_encoding_keeps_only_unreserved_characters() {
        assert_eq!(encode_uri_component("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(
            encode_uri_component("a b/c?d=e&f#g"),
            "a%20b%2Fc%3Fd%3De%26f%23g"
        );
        assert_eq!(
            encode_uri_component("Bücher.example"),
            "B%C3%BCcher.example"
        );
    }
}
