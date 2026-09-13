//! Local REST API for the ZimaScope agent.
//!
//! The API is versioned under `/v1`, JSON-only, and served on a Unix socket.
//! Collection is never blocked by API work: batches are ingested into SQLite
//! (ADR-0002) and every read endpoint answers from that storage.
//!
//! Conventions:
//!
//! - Resources are plural nouns; item resources use the natural key
//!   (`/v1/flows/{id}`, `/v1/endpoints/{ip}`, `/v1/domains/{domain}`).
//! - Lists are offset-paginated with `limit` and `offset`, plus deterministic
//!   tie-breaking in every sort order.
//! - Failures use RFC 9457 `application/problem+json`.
//! - `GET /v1/stream` pushes one `tick` per collection interval over SSE.
//! - Destructive operations require an explicit precondition
//!   (`DELETE /v1/history?confirm=true` returns `428` otherwise).

pub mod dto;
mod error;
mod settings;

mod application;
mod db;

use std::{
    collections::HashMap,
    convert::Infallible,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use axum::{
    Json, Router,
    extract::{
        FromRequest, FromRequestParts, OriginalUri, Path as AxumPath, Query, Request, State,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{any, delete, get, post},
};
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};
use tower_http::{
    compression::{
        CompressionLayer,
        predicate::{NotForContentType, Predicate, SizeAbove},
    },
    services::{ServeDir, ServeFile},
};

use zimascope_common::{
    kernel_abi::{BucketKey, RuleAction, RuleState},
    model::{AddressScope, CollectionBatch, TrafficCounters},
};

use crate::{
    FingerprintLibrary, PolicyHandle, SharedFingerprints,
    cgroup::CgroupIndex,
    policy::{
        ActionSpec, MAX_TRAFFIC_RULES, RuleDirection, TrafficRule, action_from_name, action_name,
        compile, validate_rule,
    },
    proxy::ProxyResolver,
    query::{
        Coverage, EvidenceResolver, KernelPlan, MatchTarget, Resolution, ResolveContext,
        ResolveError, Selector, SystemEvidenceResolver,
    },
};

use self::{
    db::{Db, StreamEvent, TrafficRuleDraft, TrafficRuleRecord},
    dto::{
        API_VERSION, ApplicationDetailDto, ApplicationSummaryDto, AuditEntryDto, ClearHistoryQuery,
        CollectorHealthDto, ConnectionDto, CreateExportRequest, CreateTrafficRuleRequest,
        DomainDetailDto, DomainSummaryDto, EndpointDetailDto, EndpointSummaryDto,
        EnforcementStatusDto, EnrichmentStatusDto, ExportTaskDto, FlowDto, FlowQuery, OverviewDto,
        Page, ResolveTrafficRuleDto, ResolveTrafficRuleRequest, ResolvedTargetDto,
        ServiceStatusDto, SettingsSummaryDto, StreamQuery, TimeRange, TimelineDto,
        TrafficRuleCountersDto, TrafficRuleDto, UpdateTrafficRuleRequest, collector_state_name,
        unix_millis,
    },
    error::ApiError,
    settings::{Settings, SettingsPatch},
};

pub use self::{db::ApiConfig, dto::ExportFormat, error::PROBLEM_CONTENT_TYPE};

/// Number of collection intervals buffered per SSE subscriber before lagging
/// subscribers are asked to resync over REST.
const STREAM_CHANNEL_CAPACITY: usize = 64;

/// Cloneable shared state for every API handler.
#[derive(Clone)]
pub struct ApiState {
    inner: Arc<Mutex<Inner>>,
    events: broadcast::Sender<Arc<StreamEvent>>,
}

struct Inner {
    db: Db,
    settings: Settings,
    settings_version: u64,
    collector_error: Option<String>,
    started_at: SystemTime,
    version: String,
    fingerprints: SharedFingerprints,
    fingerprints_path: Option<std::path::PathBuf>,
    proxy: ProxyResolver,
    policy_handle: Option<PolicyHandle>,
    policy: PolicyRuntime,
    cgroups: CgroupIndex,
    /// Cumulative policy drops since startup, accumulated from the interval
    /// deltas carried by every collection batch.
    policy_drops: TrafficCounters,
}

/// Last known Traffic Rule enforcement state.
#[derive(Clone, Debug, Default)]
struct PolicyRuntime {
    applied_revision: u64,
    active_rules: usize,
    unresolved: HashMap<u32, String>,
    last_error: Option<String>,
}

impl ApiState {
    pub fn new(config: ApiConfig) -> Self {
        let (events, _) = broadcast::channel(STREAM_CHANNEL_CAPACITY);
        let db = match Db::open(&config) {
            Ok(db) => db,
            Err(error) => {
                let fallback = ApiConfig {
                    database: None,
                    ..config.clone()
                };
                let mut db =
                    Db::open(&fallback).expect("in-memory storage initializes without a database");
                db.set_database_error(format!("{error:#}"));
                db
            }
        };
        let (settings, settings_version) = db.load_settings().ok().flatten().unwrap_or_default();
        let proxy = ProxyResolver::start();
        proxy.configure(
            settings.proxy.enabled,
            &settings.proxy.controller_url,
            &settings.proxy.secret,
        );

        Self {
            inner: Arc::new(Mutex::new(Inner {
                db,
                settings,
                settings_version,
                collector_error: None,
                started_at: SystemTime::now(),
                version: config.version,
                fingerprints: config.fingerprints,
                fingerprints_path: config.fingerprints_path,
                proxy,
                policy_handle: None,
                policy: PolicyRuntime::default(),
                cgroups: CgroupIndex::default(),
                policy_drops: TrafficCounters::default(),
            })),
            events,
        }
    }

    /// Attaches the collector control handle so rule changes can be applied.
    pub fn set_policy_handle(&self, handle: PolicyHandle) {
        self.lock().policy_handle = Some(handle);
    }

    /// Compiles the persisted rules and applies them through the collector.
    ///
    /// Failures are recorded for `/v1/status`; rules stay persisted either way.
    pub async fn apply_policy(&self) -> anyhow::Result<crate::policy::ApplySummary> {
        let (handle, program, unresolved) = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            let Some(handle) = inner.policy_handle.clone() else {
                inner.policy.last_error = Some("collector is not running".to_owned());
                anyhow::bail!("collector is not running");
            };

            let master = inner.settings.traffic_rules.enabled;
            let revision = inner.db.rules_revision();
            let rules: Vec<TrafficRule> = inner
                .db
                .list_traffic_rules()?
                .into_iter()
                .map(|record| record.rule)
                .collect();

            let mut resolver = SystemEvidenceResolver::new(&mut inner.cgroups, &inner.db);
            let compiled = compile(&rules, &mut resolver, revision, master)
                .map_err(|error| anyhow::anyhow!(error))?;
            let unresolved = compiled
                .unresolved
                .iter()
                .map(|rule| (rule.rule_id, rule.reason.clone()))
                .collect();
            (handle, compiled.policy, unresolved)
        };

        match handle.apply(program).await {
            Ok(summary) => {
                let mut inner = self.lock();
                inner.policy.applied_revision = summary.revision;
                inner.policy.active_rules = summary.rules;
                inner.policy.unresolved = unresolved;
                inner.policy.last_error = None;
                Ok(summary)
            }
            Err(error) => {
                let mut inner = self.lock();
                inner.policy.last_error = Some(format!("{error:#}"));
                Err(error)
            }
        }
    }

    /// Feeds one collection interval into storage and notifies SSE
    /// subscribers.
    pub fn ingest_batch(&self, batch: CollectionBatch) {
        let publish = self.events.receiver_count() > 0;
        let event = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            inner.policy_drops.packets = inner
                .policy_drops
                .packets
                .saturating_add(batch.health.kernel.policy_dropped_packets);
            inner.policy_drops.bytes = inner
                .policy_drops
                .bytes
                .saturating_add(batch.health.kernel.policy_dropped_bytes);
            inner
                .db
                .ingest(batch, &inner.settings, &inner.proxy, publish)
        };
        let _ = self.events.send(Arc::new(event));
    }

    /// Records why collection is unavailable so `/v1/status` can explain it.
    pub fn set_collector_error(&self, error: impl Into<String>) {
        self.lock().collector_error = Some(error.into());
    }

    fn subscribe(&self) -> broadcast::Receiver<Arc<StreamEvent>> {
        self.events.subscribe()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Inner {
    fn status(&self) -> ServiceStatusDto {
        let health = self.db.health();
        let service = if self.collector_error.is_some() {
            "unavailable"
        } else {
            match health {
                Some(health) => collector_state_name(health.state),
                None => "starting",
            }
        };
        let (enrichment, enrichment_error) = self.db.enrichment_status();
        let (fingerprint_rules, fingerprints_custom, fingerprint_services) = {
            let library = self
                .fingerprints
                .read()
                .unwrap_or_else(|error| error.into_inner());
            (
                library.rule_count(),
                library.is_custom(),
                library.services(),
            )
        };
        let proxy = self.proxy.status();

        ServiceStatusDto {
            service,
            version: self.version.clone(),
            api_version: API_VERSION,
            started_at: unix_millis(self.started_at),
            uptime_seconds: SystemTime::now()
                .duration_since(self.started_at)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
            last_batch_at: self.db.last_batch_at().map(unix_millis),
            batch_sequence: self.db.batch_sequence(),
            collector_error: self.collector_error.clone(),
            database_error: self.db.database_error().map(ToOwned::to_owned),
            collector: health.map(CollectorHealthDto::from_health),
            enrichment: EnrichmentStatusDto {
                database_version: enrichment
                    .database_version
                    .as_ref()
                    .map(ToString::to_string),
                loaded_at: enrichment.database_loaded_at.map(unix_millis),
                error: enrichment_error,
            },
            fingerprints: dto::FingerprintStatusDto {
                rules: fingerprint_rules,
                custom: fingerprints_custom,
                services: fingerprint_services,
            },
            proxy: dto::ProxyStatusDto {
                enabled: proxy.enabled,
                reachable: proxy.reachable,
                mapped: proxy.mapped,
                last_error: proxy.last_error,
            },
            enforcement: EnforcementStatusDto {
                enabled: self.settings.traffic_rules.enabled,
                available: self.policy_handle.is_some(),
                revision: self.policy.applied_revision,
                rules_total: self
                    .db
                    .list_traffic_rules()
                    .map(|rules| rules.len())
                    .unwrap_or(0),
                rules_active: self.policy.active_rules,
                rules_unresolved: self.policy.unresolved.len(),
                dropped_packets: self.policy_drops.packets,
                dropped_bytes: self.policy_drops.bytes,
                last_error: self.policy.last_error.clone(),
            },
            settings: SettingsSummaryDto {
                enabled: self.settings.enabled,
                boundary_interfaces: self.settings.boundary.interfaces.clone(),
                domain_observation: self.settings.domains.enabled,
                history_enabled: self.settings.history.enabled,
                retention_days: self.settings.history.retention_days,
            },
            recent_operations: self
                .db
                .audit_entries()
                .map(|(action, outcome, at)| AuditEntryDto {
                    at: unix_millis(at),
                    action,
                    outcome,
                })
                .collect(),
        }
    }
}

/// Builds the complete `/v1` router (API only).
pub fn router(state: ApiState) -> Router {
    api_routes(state)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(compression_layer())
}

/// Builds the production router: the `/v1` API plus the built frontend served
/// from `ui_dir` on the same port. Unknown `/v1` paths still answer with RFC
/// 9457 problem details; every other path falls back to `index.html` so the
/// hash-routed SPA boots from any URL.
pub fn router_with_ui(state: ApiState, ui_dir: &Path) -> Router {
    let index = ui_dir.join("index.html");
    api_routes(state)
        .route("/v1/{*path}", any(not_found))
        .fallback_service(ServeDir::new(ui_dir).not_found_service(ServeFile::new(index)))
        .method_not_allowed_fallback(method_not_allowed)
        .layer(compression_layer())
}

/// Gzip for every response that benefits, including the SSE tick stream.
///
/// The default predicate deliberately skips `text/event-stream`; the tick
/// payload is the largest thing this API serves, so it opts back in. gRPC and
/// images stay uncompressed, and tiny responses stay below the size floor.
fn compression_layer() -> CompressionLayer<impl Predicate> {
    let predicate = SizeAbove::default()
        .and(NotForContentType::GRPC)
        .and(NotForContentType::IMAGES);
    CompressionLayer::new().gzip(true).compress_when(predicate)
}

/// All API routes, in one place so the dev and production routers stay in
/// sync.
fn api_routes(state: ApiState) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/overview", get(overview))
        .route("/v1/stream", get(stream))
        .route("/v1/flows", get(list_flows))
        .route("/v1/flows/{id}", get(get_flow))
        .route("/v1/connections", get(list_connections))
        .route("/v1/endpoints", get(list_endpoints))
        .route("/v1/endpoints/{ip}", get(get_endpoint))
        .route("/v1/endpoints/{ip}/timeline", get(get_endpoint_timeline))
        .route("/v1/domains", get(list_domains))
        .route("/v1/domains/{domain}", get(get_domain))
        .route("/v1/domains/{domain}/timeline", get(get_domain_timeline))
        .route("/v1/applications", get(list_applications))
        .route("/v1/applications/{id}", get(get_application))
        .route(
            "/v1/applications/{id}/timeline",
            get(get_application_timeline),
        )
        .route(
            "/v1/settings",
            get(get_settings).put(put_settings).patch(patch_settings),
        )
        .route(
            "/v1/fingerprints",
            get(get_fingerprints)
                .put(put_fingerprints)
                .delete(reset_fingerprints),
        )
        .route("/v1/exports", get(list_exports).post(create_export))
        .route("/v1/exports/{id}", get(get_export).delete(delete_export))
        .route("/v1/exports/{id}/content", get(get_export_content))
        .route(
            "/v1/traffic-rules",
            get(list_traffic_rules).post(create_traffic_rule),
        )
        .route("/v1/traffic-rules/resolve", post(resolve_traffic_rule))
        .route(
            "/v1/traffic-rules/{id}",
            get(get_traffic_rule)
                .patch(update_traffic_rule)
                .delete(delete_traffic_rule),
        )
        .route("/v1/history", delete(clear_history))
        .with_state(state)
}

/// Binds the API to a local Unix socket, replacing a stale socket file.
#[cfg(unix)]
pub fn bind_unix(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(_) => {}
    }

    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

/// Serves the API on an already-bound Unix listener.
#[cfg(unix)]
pub async fn serve_unix(
    listener: tokio::net::UnixListener,
    state: ApiState,
) -> std::io::Result<()> {
    axum::serve(listener, router(state)).await
}

// ------------------------------------------------------------------ handlers

async fn status(State(state): State<ApiState>) -> Json<ServiceStatusDto> {
    Json(state.lock().status())
}

#[derive(serde::Deserialize)]
struct OverviewQuery {
    range: Option<TimeRange>,
    #[serde(default, deserialize_with = "dto::deserialize_scope_list")]
    exclude_scope: Vec<AddressScope>,
}

async fn list_connections(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<FlowQuery>,
) -> Result<Json<Page<ConnectionDto>>, ApiError> {
    state.lock().db.list_connections(&query).map(Json)
}

async fn overview(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<OverviewQuery>,
) -> Result<Json<OverviewDto>, ApiError> {
    let range = query.range.unwrap_or_default();
    state
        .lock()
        .db
        .overview(range, &query.exclude_scope, SystemTime::now())
        .map(Json)
}

/// Streams one `tick` per collection interval over Server-Sent Events.
///
/// Reconnects (`Last-Event-ID`) and lagging subscribers receive a `resync`
/// event instead of silently missing updates; clients should then reload
/// `/v1/flows`, `/v1/overview` or `/v1/status` and keep consuming the stream.
async fn stream(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<StreamQuery>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let filter = query.filter();
    let receiver = state.subscribe();
    let resumed = headers.contains_key("last-event-id");
    let initial = resumed.then(|| Ok(resync_event("client reconnected; resync required")));

    let updates = BroadcastStream::new(receiver).map(move |message| {
        let event = match message {
            Ok(event) => tick_event(&event, &filter),
            Err(_) => resync_event("subscriber fell behind; resync required"),
        };
        Ok::<Event, Infallible>(event)
    });

    let stream = tokio_stream::iter(initial).chain(updates);
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

fn tick_event(event: &StreamEvent, filter: &dto::StreamFilter) -> Event {
    match event.tick_json(filter) {
        Some(data) => Event::default()
            .id(event.sequence.to_string())
            .event("tick")
            .data(data.as_ref()),
        None => resync_event("event serialization failed"),
    }
}

fn resync_event(reason: &str) -> Event {
    let data = serde_json::json!({ "reason": reason }).to_string();
    Event::default().event("resync").data(data)
}

async fn list_flows(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<FlowQuery>,
) -> Result<Json<Page<FlowDto>>, ApiError> {
    state.lock().db.list_flows(&query).map(Json)
}

async fn get_flow(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<FlowDto>, ApiError> {
    state.lock().db.get_flow(&id).map(Json)
}

async fn list_endpoints(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<FlowQuery>,
) -> Result<Json<Page<EndpointSummaryDto>>, ApiError> {
    state.lock().db.list_endpoints(&query).map(Json)
}

async fn get_endpoint(
    State(state): State<ApiState>,
    AxumPath(ip): AxumPath<String>,
) -> Result<Json<EndpointDetailDto>, ApiError> {
    state.lock().db.get_endpoint(&ip).map(Json)
}

#[derive(serde::Deserialize)]
struct TimelineQuery {
    range: Option<TimeRange>,
}

async fn get_endpoint_timeline(
    State(state): State<ApiState>,
    AxumPath(ip): AxumPath<String>,
    ApiQuery(query): ApiQuery<TimelineQuery>,
) -> Result<Json<TimelineDto>, ApiError> {
    let range = query.range.unwrap_or_default();
    state
        .lock()
        .db
        .endpoint_timeline(&ip, range, SystemTime::now())
        .map(Json)
}

async fn get_domain_timeline(
    State(state): State<ApiState>,
    AxumPath(domain): AxumPath<String>,
    ApiQuery(query): ApiQuery<TimelineQuery>,
) -> Result<Json<TimelineDto>, ApiError> {
    let range = query.range.unwrap_or_default();
    state
        .lock()
        .db
        .domain_timeline(&domain, range, SystemTime::now())
        .map(Json)
}

async fn list_domains(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<FlowQuery>,
) -> Result<Json<Page<DomainSummaryDto>>, ApiError> {
    state.lock().db.list_domains(&query).map(Json)
}

async fn get_domain(
    State(state): State<ApiState>,
    AxumPath(domain): AxumPath<String>,
) -> Result<Json<DomainDetailDto>, ApiError> {
    state.lock().db.get_domain(&domain).map(Json)
}

async fn list_applications(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<FlowQuery>,
) -> Result<Json<Page<ApplicationSummaryDto>>, ApiError> {
    state.lock().db.list_applications(&query).map(Json)
}

async fn get_application(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ApplicationDetailDto>, ApiError> {
    state.lock().db.get_application(&id).map(Json)
}

async fn get_application_timeline(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
    ApiQuery(query): ApiQuery<TimelineQuery>,
) -> Result<Json<TimelineDto>, ApiError> {
    let range = query.range.unwrap_or_default();
    state
        .lock()
        .db
        .application_timeline(&id, range, SystemTime::now())
        .map(Json)
}

async fn get_settings(State(state): State<ApiState>) -> Json<Settings> {
    Json(state.lock().settings.clone())
}

async fn put_settings(
    State(state): State<ApiState>,
    ApiJson(body): ApiJson<Settings>,
) -> Result<Json<Settings>, ApiError> {
    let settings = {
        let mut inner = state.lock();
        let mut settings = body;
        settings.normalize();
        settings.validate()?;
        apply_settings(&mut inner, settings)?;
        inner.settings.clone()
    };
    let _ = state.apply_policy().await;
    Ok(Json(settings))
}

async fn patch_settings(
    State(state): State<ApiState>,
    ApiJson(patch): ApiJson<SettingsPatch>,
) -> Result<Json<Settings>, ApiError> {
    let settings = {
        let mut inner = state.lock();
        let mut settings = inner.settings.clone();
        patch.apply(&mut settings);
        settings.normalize();
        settings.validate()?;
        apply_settings(&mut inner, settings)?;
        inner.settings.clone()
    };
    let _ = state.apply_policy().await;
    Ok(Json(settings))
}

fn apply_settings(inner: &mut Inner, settings: Settings) -> Result<(), ApiError> {
    inner.settings_version += 1;
    inner.db.save_settings(&settings, inner.settings_version)?;
    inner.proxy.configure(
        settings.proxy.enabled,
        &settings.proxy.controller_url,
        &settings.proxy.secret,
    );
    inner.settings = settings;
    Ok(())
}

impl Inner {
    /// Resolves one selector through the host's evidence sources.
    fn resolve_selector(&mut self, selector: &Selector) -> Result<Resolution, ResolveError> {
        let mut resolver = SystemEvidenceResolver::new(&mut self.cgroups, &self.db);
        resolver.resolve(
            selector,
            &ResolveContext {
                now: SystemTime::now(),
            },
        )
    }

    /// Derived enforcement state for one rule.
    fn traffic_rule_state(&self, rule: &TrafficRule) -> (&'static str, Option<String>) {
        if self.policy_handle.is_none() {
            return ("unavailable", Some("collector is not running".to_owned()));
        }
        if !self.settings.traffic_rules.enabled {
            return (
                "bypassed",
                Some("Traffic Rule enforcement is disabled".to_owned()),
            );
        }
        if !rule.enabled {
            return ("bypassed", Some("rule is disabled".to_owned()));
        }
        if let Some(reason) = self.policy.unresolved.get(&rule.id) {
            return ("unresolved", Some(reason.clone()));
        }
        ("active", None)
    }

    fn traffic_rule_dto(
        &self,
        record: &TrafficRuleRecord,
        counters: Option<RuleState>,
    ) -> TrafficRuleDto {
        let rule = &record.rule;
        let (state, state_reason) = self.traffic_rule_state(rule);
        let (rate_bytes_per_s, burst_bytes) = rule.action.rates();

        TrafficRuleDto {
            id: rule.id,
            action: action_name(rule.action.action()),
            direction: rule.direction.as_str(),
            selector: rule.selector.clone(),
            rate_bytes_per_s,
            burst_bytes,
            enabled: rule.enabled,
            state,
            state_reason,
            created_at: unix_millis(record.created_at),
            updated_at: unix_millis(record.updated_at),
            counters: counters.map(|counters| TrafficRuleCountersDto {
                matched_packets: counters.matched_packets,
                matched_bytes: counters.matched_bytes,
                dropped_packets: counters.dropped_packets,
                dropped_bytes: counters.dropped_bytes,
            }),
        }
    }
}

/// Returns the active fingerprint library document.
async fn get_fingerprints(State(state): State<ApiState>) -> Response {
    let raw = state
        .lock()
        .fingerprints
        .read()
        .unwrap_or_else(|error| error.into_inner())
        .raw()
        .to_owned();
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        raw,
    )
        .into_response()
}

/// Replaces the fingerprint library; persists it when a path is configured.
async fn put_fingerprints(
    State(state): State<ApiState>,
    body: String,
) -> Result<Response, ApiError> {
    let library = FingerprintLibrary::from_json(&body)
        .map_err(|error| ApiError::unprocessable(error.to_string()))?;
    let rules = library.rule_count();
    let mut inner = state.lock();
    if let Some(path) = inner.fingerprints_path.clone() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                ApiError::internal(format!("create fingerprint directory: {error}"))
            })?;
        }
        std::fs::write(&path, &body)
            .map_err(|error| ApiError::internal(format!("persist fingerprints: {error}")))?;
    }
    *inner
        .fingerprints
        .write()
        .unwrap_or_else(|error| error.into_inner()) = library;
    inner
        .db
        .record_operation("fingerprints.update", "completed");
    Ok((StatusCode::OK, Json(serde_json::json!({ "rules": rules }))).into_response())
}

/// Restores the embedded default library and removes the persisted file.
async fn reset_fingerprints(State(state): State<ApiState>) -> StatusCode {
    let mut inner = state.lock();
    if let Some(path) = &inner.fingerprints_path {
        let _ = std::fs::remove_file(path);
    }
    *inner
        .fingerprints
        .write()
        .unwrap_or_else(|error| error.into_inner()) = FingerprintLibrary::default_library();
    inner.db.record_operation("fingerprints.reset", "completed");
    StatusCode::NO_CONTENT
}

async fn list_exports(State(state): State<ApiState>) -> Result<Json<Vec<ExportTaskDto>>, ApiError> {
    state.lock().db.list_exports().map(Json)
}

async fn create_export(
    State(state): State<ApiState>,
    ApiJson(body): ApiJson<CreateExportRequest>,
) -> Result<Response, ApiError> {
    let mut inner = state.lock();
    let task = inner.db.create_export(&body)?;
    let location = HeaderValue::from_str(&format!("/v1/exports/{}", task.id))
        .map_err(|error| ApiError::internal(format!("invalid export location: {error}")))?;
    Ok((
        StatusCode::CREATED,
        [(header::LOCATION, location)],
        Json(task),
    )
        .into_response())
}

async fn get_export(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<ExportTaskDto>, ApiError> {
    state.lock().db.get_export(&id).map(Json)
}

async fn get_export_content(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let content = state.lock().db.export_content(&id)?;
    let content_type = HeaderValue::from_str(&content.content_type)
        .map_err(|error| ApiError::internal(format!("invalid content type: {error}")))?;
    let disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", content.file_name))
            .map_err(|error| ApiError::internal(format!("invalid export file name: {error}")))?;
    Ok((
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_DISPOSITION, disposition),
        ],
        content.bytes,
    )
        .into_response())
}

async fn delete_export(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<StatusCode, ApiError> {
    state.lock().db.delete_export(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------ traffic rules

async fn list_traffic_rules(
    State(state): State<ApiState>,
) -> Result<Json<Vec<TrafficRuleDto>>, ApiError> {
    let (records, keys, handle) = {
        let inner = state.lock();
        let records = inner.db.list_traffic_rules()?;
        let keys: Vec<BucketKey> = records
            .iter()
            .flat_map(|record| rule_bucket_keys(&record.rule))
            .collect();
        (records, keys, inner.policy_handle.clone())
    };

    let states = match handle {
        Some(handle) if !keys.is_empty() => handle
            .rule_states(&keys)
            .await
            .unwrap_or_else(|_| vec![None; keys.len()]),
        _ => Vec::new(),
    };

    let inner = state.lock();
    let mut rules = Vec::with_capacity(records.len());
    let mut position = 0;
    for record in &records {
        let key_count = rule_bucket_keys(&record.rule).len();
        let counters = states.get(position).copied().flatten();
        position += key_count;
        rules.push(inner.traffic_rule_dto(record, counters));
    }
    Ok(Json(rules))
}

async fn get_traffic_rule(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<u32>,
) -> Result<Json<TrafficRuleDto>, ApiError> {
    let record = state.lock().db.traffic_rule(i64::from(id))?;
    let counters = rule_counters(&state, &record.rule).await;
    let inner = state.lock();
    Ok(Json(inner.traffic_rule_dto(&record, counters)))
}

async fn create_traffic_rule(
    State(state): State<ApiState>,
    ApiJson(request): ApiJson<CreateTrafficRuleRequest>,
) -> Result<(StatusCode, Json<TrafficRuleDto>), ApiError> {
    let draft = draft_from_create(&request)?;
    let record = {
        let mut inner = state.lock();
        if inner.db.list_traffic_rules()?.len() >= MAX_TRAFFIC_RULES {
            return Err(ApiError::conflict(format!(
                "at most {MAX_TRAFFIC_RULES} Traffic Rules are supported"
            )));
        }
        let record = inner.db.insert_traffic_rule(&draft)?;
        inner
            .db
            .record_operation("traffic_rule.create", "completed");
        record
    };

    let _ = state.apply_policy().await;
    let inner = state.lock();
    Ok((
        StatusCode::CREATED,
        Json(inner.traffic_rule_dto(&record, None)),
    ))
}

async fn update_traffic_rule(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<u32>,
    ApiJson(request): ApiJson<UpdateTrafficRuleRequest>,
) -> Result<Json<TrafficRuleDto>, ApiError> {
    let draft = {
        let inner = state.lock();
        let record = inner.db.traffic_rule(i64::from(id))?;
        draft_from_update(&record.rule, &request)?
    };
    let record = {
        let mut inner = state.lock();
        let record = inner.db.update_traffic_rule(i64::from(id), &draft)?;
        inner
            .db
            .record_operation("traffic_rule.update", "completed");
        record
    };

    let _ = state.apply_policy().await;
    let counters = rule_counters(&state, &record.rule).await;
    let inner = state.lock();
    Ok(Json(inner.traffic_rule_dto(&record, counters)))
}

async fn delete_traffic_rule(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<u32>,
) -> Result<StatusCode, ApiError> {
    {
        let mut inner = state.lock();
        inner.db.delete_traffic_rule(i64::from(id))?;
        inner
            .db
            .record_operation("traffic_rule.delete", "completed");
    }
    let _ = state.apply_policy().await;
    Ok(StatusCode::NO_CONTENT)
}

/// Reports what a selector would enforce before a rule is created.
///
/// Resolution and the capacity bound run through the same seam as
/// compilation, so a `complete` answer here matches what would be applied.
async fn resolve_traffic_rule(
    State(state): State<ApiState>,
    ApiJson(request): ApiJson<ResolveTrafficRuleRequest>,
) -> Result<Json<ResolveTrafficRuleDto>, ApiError> {
    let direction = RuleDirection::from_name(&request.direction).ok_or_else(|| {
        ApiError::unprocessable(format!("unknown direction {:?}", request.direction))
    })?;
    request
        .selector
        .validate()
        .map_err(ApiError::unprocessable)?;
    let plan = request.selector.kernel_plan();
    if let KernelPlan::Unsupported { reason } = plan {
        return Err(ApiError::unprocessable(reason));
    }

    let mut inner = state.lock();
    let mut resolution = inner
        .resolve_selector(&request.selector)
        .map_err(|ResolveError::Unavailable { reason }| ApiError::internal(reason))?;
    if matches!(&resolution.coverage, Coverage::Complete)
        && let Err(reason) = crate::policy::check_target_capacity(&resolution.targets, direction)
    {
        resolution.targets.clear();
        resolution.coverage = Coverage::Unresolved { reason };
    }

    let (coverage, reason) = match resolution.coverage {
        Coverage::Complete => ("complete", None),
        Coverage::Unresolved { reason } => ("unresolved", Some(reason)),
    };
    Ok(Json(ResolveTrafficRuleDto {
        plan: plan.name(),
        targets: resolution.targets.iter().map(resolved_target_dto).collect(),
        coverage,
        reason,
        expires_at: resolution.expires_at.map(unix_millis),
    }))
}

fn resolved_target_dto(target: &MatchTarget) -> ResolvedTargetDto {
    match target {
        MatchTarget::Endpoint { address, port } => ResolvedTargetDto {
            kind: "endpoint",
            address: Some(address.to_string()),
            port: *port,
            prefix_len: None,
            cgroup_id: None,
            comm: None,
        },
        MatchTarget::Cidr {
            address,
            prefix_len,
        } => ResolvedTargetDto {
            kind: "cidr",
            address: Some(address.to_string()),
            port: None,
            prefix_len: Some(*prefix_len),
            cgroup_id: None,
            comm: None,
        },
        MatchTarget::AppCgroup { cgroup_id } => ResolvedTargetDto {
            kind: "application_cgroup",
            address: None,
            port: None,
            prefix_len: None,
            cgroup_id: Some(*cgroup_id),
            comm: None,
        },
        MatchTarget::AppComm { comm } => ResolvedTargetDto {
            kind: "application_comm",
            address: None,
            port: None,
            prefix_len: None,
            cgroup_id: None,
            comm: Some(zimascope_common::model::comm_text(comm).into()),
        },
    }
}

async fn rule_counters(state: &ApiState, rule: &TrafficRule) -> Option<RuleState> {
    let (handle, keys) = {
        let inner = state.lock();
        (inner.policy_handle.clone(), rule_bucket_keys(rule))
    };
    let handle = handle?;
    handle
        .rule_states(&keys)
        .await
        .ok()?
        .into_iter()
        .flatten()
        .next()
}

fn rule_bucket_keys(rule: &TrafficRule) -> Vec<BucketKey> {
    rule.direction
        .directions()
        .iter()
        .map(|direction| BucketKey {
            rule_id: rule.id,
            direction: *direction as u8,
            reserved: [0; 3],
        })
        .collect()
}

fn draft_from_create(request: &CreateTrafficRuleRequest) -> Result<TrafficRuleDraft, ApiError> {
    let kind = action_from_name(&request.action)
        .ok_or_else(|| ApiError::unprocessable(format!("unknown action {:?}", request.action)))?;
    let direction = RuleDirection::from_name(&request.direction).ok_or_else(|| {
        ApiError::unprocessable(format!("unknown direction {:?}", request.direction))
    })?;
    let action = match kind {
        RuleAction::Limit => ActionSpec::Limit {
            rate_bytes_per_s: request.rate_bytes_per_s.unwrap_or(0),
            burst_bytes: request.rate_bytes_per_s.unwrap_or(0),
        },
        RuleAction::Block => {
            if request.rate_bytes_per_s.is_some() {
                return Err(ApiError::unprocessable("block rules carry no rate"));
            }
            ActionSpec::Block
        }
    };
    let selector = request.selector.clone();
    let draft = TrafficRuleDraft {
        action,
        direction,
        selector,
        enabled: request.enabled.unwrap_or(true),
    };
    validate_draft(&draft)?;
    Ok(draft)
}

fn draft_from_update(
    existing: &TrafficRule,
    request: &UpdateTrafficRuleRequest,
) -> Result<TrafficRuleDraft, ApiError> {
    let direction = match &request.direction {
        Some(name) => RuleDirection::from_name(name)
            .ok_or_else(|| ApiError::unprocessable(format!("unknown direction {name:?}")))?,
        None => existing.direction,
    };
    let selector = match &request.selector {
        Some(selector) => selector.clone(),
        None => existing.selector.clone(),
    };
    let action = match &request.action {
        Some(name) => match action_from_name(name)
            .ok_or_else(|| ApiError::unprocessable(format!("unknown action {name:?}")))?
        {
            RuleAction::Limit => {
                let (rate, _) = existing.action.rates();
                let rate = request.rate_bytes_per_s.unwrap_or(rate);
                ActionSpec::Limit {
                    rate_bytes_per_s: rate,
                    burst_bytes: rate,
                }
            }
            RuleAction::Block => {
                if request.rate_bytes_per_s.is_some() {
                    return Err(ApiError::unprocessable("block rules carry no rate"));
                }
                ActionSpec::Block
            }
        },
        None => match &existing.action {
            ActionSpec::Limit {
                rate_bytes_per_s, ..
            } => {
                let rate = request.rate_bytes_per_s.unwrap_or(*rate_bytes_per_s);
                ActionSpec::Limit {
                    rate_bytes_per_s: rate,
                    burst_bytes: rate,
                }
            }
            ActionSpec::Block => {
                if request.rate_bytes_per_s.is_some() {
                    return Err(ApiError::unprocessable("block rules carry no rate"));
                }
                ActionSpec::Block
            }
        },
    };
    let draft = TrafficRuleDraft {
        action,
        direction,
        selector,
        enabled: request.enabled.unwrap_or(existing.enabled),
    };
    validate_draft(&draft)?;
    Ok(draft)
}

fn validate_draft(draft: &TrafficRuleDraft) -> Result<(), ApiError> {
    let rule = TrafficRule {
        id: 0,
        action: draft.action.clone(),
        direction: draft.direction,
        selector: draft.selector.clone(),
        enabled: draft.enabled,
    };
    validate_rule(&rule).map_err(ApiError::unprocessable)
}

async fn clear_history(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<ClearHistoryQuery>,
) -> Result<StatusCode, ApiError> {
    if !query.confirm {
        return Err(ApiError::precondition_required(
            "clearing history deletes Flows, domain evidence and exports; retry with confirm=true",
        ));
    }
    state.lock().db.clear_history();
    Ok(StatusCode::NO_CONTENT)
}

async fn not_found(method: Method, OriginalUri(uri): OriginalUri) -> ApiError {
    ApiError::not_found(format!("no route for {method} {}", uri.path())).with_instance(&uri)
}

async fn method_not_allowed(method: Method, OriginalUri(uri): OriginalUri) -> ApiError {
    ApiError::method_not_allowed(format!("{method} is not supported by {}", uri.path()))
        .with_instance(&uri)
}

// --------------------------------------------------------------- extractors

/// Query extractor that renders rejections as problem details.
pub struct ApiQuery<T>(pub T);

impl<S, T> FromRequestParts<S> for ApiQuery<T>
where
    T: serde::de::DeserializeOwned + Send,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Query::<T>::from_request_parts(parts, state)
            .await
            .map(|Query(value)| ApiQuery(value))
            .map_err(|rejection| ApiError::bad_request(rejection.body_text()))
    }
}

/// JSON body extractor that renders rejections as problem details.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| ApiJson(value))
            .map_err(|rejection| ApiError::with_status(rejection.status(), rejection.body_text()))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        num::NonZeroU32,
        time::{Duration, Instant, SystemTime},
    };

    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use zimascope_common::model::{
        ApplicationRef, AssociationConfidence, CollectorHealth, CollectorState, DomainEvidence,
        DomainObservation, Endpoint, FlowDirection, FlowKey, FlowState, FlowUpdate,
        InterfaceHealth, Protocol, TrafficCounters,
    };

    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn state() -> ApiState {
        ApiState::new(ApiConfig {
            version: "0.0.0-test".to_owned(),
            flow_capacity: 128,
            export_ttl: Duration::from_secs(3600),
            geoip_database: None,
            database: None,
            ..ApiConfig::default()
        })
    }

    fn state_with_export_ttl(ttl: Duration) -> ApiState {
        ApiState::new(ApiConfig {
            version: "0.0.0-test".to_owned(),
            flow_capacity: 128,
            export_ttl: ttl,
            geoip_database: None,
            database: None,
            ..ApiConfig::default()
        })
    }

    fn flow(
        direction: FlowDirection,
        source: (&str, u16),
        destination: (&str, u16),
        packets: u64,
        bytes: u64,
        age: Duration,
    ) -> FlowUpdate {
        flow_with(
            Protocol::Tcp,
            direction,
            source,
            destination,
            packets,
            bytes,
            age,
        )
    }

    fn flow_with(
        protocol: Protocol,
        direction: FlowDirection,
        source: (&str, u16),
        destination: (&str, u16),
        packets: u64,
        bytes: u64,
        age: Duration,
    ) -> FlowUpdate {
        let now = Instant::now();
        FlowUpdate {
            key: FlowKey {
                source: Endpoint {
                    address: source.0.parse().expect("source address"),
                    port: Some(source.1),
                },
                destination: Endpoint {
                    address: destination.0.parse().expect("destination address"),
                    port: Some(destination.1),
                },
                interface_index: NonZeroU32::new(7).expect("non-zero ifindex"),
                protocol,
                direction,
            },
            delta: TrafficCounters { packets, bytes },
            total: TrafficCounters { packets, bytes },
            first_seen: now - age - Duration::from_secs(10),
            last_seen: now - age,
            state: FlowState::Active,
            service: None,
            application: None,
        }
    }

    fn outbound(destination: (&str, u16), packets: u64, bytes: u64, age: Duration) -> FlowUpdate {
        flow(
            FlowDirection::Outbound,
            ("10.0.0.2", 40_000),
            destination,
            packets,
            bytes,
            age,
        )
    }

    fn observation(
        domain: &str,
        address: &str,
        evidence: DomainEvidence,
        confidence: AssociationConfidence,
    ) -> DomainObservation {
        let now = Instant::now();
        DomainObservation {
            domain: domain.into(),
            address: address.parse().expect("observation address"),
            evidence,
            confidence,
            client_context: 1,
            observed_at: now,
            expires_at: now + Duration::from_secs(600),
        }
    }

    fn batch(sequence: u64, flows: Vec<FlowUpdate>) -> CollectionBatch {
        CollectionBatch {
            sequence,
            collected_at: SystemTime::now(),
            interval: Duration::from_secs(1),
            flows,
            domains: Vec::new(),
            health: CollectorHealth {
                state: CollectorState::Running,
                attached_interfaces: vec![InterfaceHealth {
                    ifindex: NonZeroU32::new(7).expect("non-zero ifindex"),
                    name: "eth0".into(),
                    ingress_attached: true,
                    egress_attached: true,
                    last_error: None,
                }],
                map_entries: 0,
                map_capacity: 128,
                kernel: Default::default(),
                gaps: Vec::new(),
                application: Default::default(),
            },
        }
    }

    fn get(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("valid request")
    }

    fn json_request(method: Method, uri: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("valid request")
    }

    async fn call(state: &ApiState, request: Request<Body>) -> Response {
        router(state.clone())
            .oneshot(request)
            .await
            .expect("router responds")
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        serde_json::from_slice(&bytes).expect("valid JSON body")
    }

    async fn body_text(response: Response) -> String {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("read body")
            .to_bytes();
        String::from_utf8(bytes.to_vec()).expect("UTF-8 body")
    }

    fn assert_problem(response: &Response, status: StatusCode) {
        assert_eq!(response.status(), status);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some(PROBLEM_CONTENT_TYPE)
        );
    }

    #[tokio::test]
    async fn status_explains_unavailable_collection() {
        let state = state();
        state.set_collector_error("BTF unavailable");

        let response = call(&state, get("/v1/status")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["service"], "unavailable");
        assert_eq!(body["collector_error"], "BTF unavailable");
        assert_eq!(body["settings"]["retention_days"], 7);
    }

    #[tokio::test]
    async fn status_reports_running_collection_after_ingest() {
        let state = state();
        state.ingest_batch(batch(1, vec![]));

        let body = body_json(call(&state, get("/v1/status")).await).await;
        assert_eq!(body["service"], "running");
        assert_eq!(body["batch_sequence"], 1);
        assert_eq!(body["collector"]["state"], "running");
        assert_eq!(body["collector"]["map"]["capacity"], 128);
        assert_eq!(body["collector"]["interfaces"][0]["name"], "eth0");
    }

    #[tokio::test]
    async fn compression_negotiates_gzip_including_sse() {
        let state = state();

        let request = Request::builder()
            .uri("/v1/status")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .expect("valid request");
        let response = call(&state, request).await;
        assert_eq!(content_encoding(&response).as_deref(), Some("gzip"));

        let request = Request::builder()
            .uri("/v1/stream")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Body::empty())
            .expect("valid request");
        let response = call(&state, request).await;
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
        assert_eq!(content_encoding(&response).as_deref(), Some("gzip"));

        let response = call(&state, get("/v1/status")).await;
        assert_eq!(content_encoding(&response), None);
    }

    fn content_encoding(response: &Response) -> Option<String> {
        response
            .headers()
            .get(header::CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    }

    #[tokio::test]
    async fn unknown_routes_and_methods_return_problem_details() {
        let response = call(&state(), get("/v1/nope")).await;
        assert_problem(&response, StatusCode::NOT_FOUND);
        let body = body_json(response).await;
        assert_eq!(body["type"], "/problems/not_found");
        assert_eq!(body["instance"], "/v1/nope");

        let response = call(
            &state(),
            Request::builder()
                .method(Method::POST)
                .uri("/v1/status")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await;
        assert_problem(&response, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn invalid_query_parameters_return_problem_details() {
        let response = call(&state(), get("/v1/flows?direction=sideways")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);

        let response = call(&state(), get("/v1/flows?sort=bogus")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);

        let response = call(&state(), get("/v1/flows?limit=0")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn flows_filter_and_paginate_with_offsets() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![
                outbound(("1.1.1.1", 443), 10, 1_000, Duration::from_secs(1)),
                outbound(("8.8.8.8", 443), 20, 2_000, Duration::from_secs(2)),
                flow(
                    FlowDirection::Inbound,
                    ("9.9.9.9", 55_000),
                    ("10.0.0.2", 443),
                    30,
                    3_000,
                    Duration::from_secs(3),
                ),
            ],
        ));

        let body = body_json(call(&state, get("/v1/flows?limit=2&offset=0")).await).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["limit"], 2);
        assert_eq!(body["offset"], 0);
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["remote"]["address"], "1.1.1.1");

        let body = body_json(call(&state, get("/v1/flows?limit=2&offset=2")).await).await;
        assert_eq!(body["total"], 3);
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["direction"], "inbound");

        let body = body_json(call(&state, get("/v1/flows?direction=inbound")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "9.9.9.9");

        let body = body_json(call(&state, get("/v1/flows?port=55000")).await).await;
        assert_eq!(body["total"], 1);

        let body = body_json(call(&state, get("/v1/flows?state=active")).await).await;
        assert_eq!(body["total"], 3);
    }

    #[tokio::test]
    async fn exclude_scope_hides_local_remotes() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![
                outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO),
                flow(
                    FlowDirection::Inbound,
                    ("192.168.1.24", 52_144),
                    ("10.0.0.2", 443),
                    5,
                    500,
                    Duration::ZERO,
                ),
            ],
        ));

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        assert_eq!(body["total"], 2);

        let body =
            body_json(call(&state, get("/v1/flows?exclude_scope=private,link_local")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "1.1.1.1");

        let body = body_json(call(&state, get("/v1/endpoints?exclude_scope=private")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["address"], "1.1.1.1");

        let body =
            body_json(call(&state, get("/v1/overview?range=15m&exclude_scope=private")).await)
                .await;
        assert_eq!(body["domain_visibility"]["flows_total"], 1);
        assert_eq!(body["totals"]["inbound"]["bytes"], 0);
        assert_eq!(body["totals"]["outbound"]["bytes"], 1_000);

        let response = call(&state, get("/v1/flows?exclude_scope=mystery")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn stream_excludes_scopes() {
        let state = state();
        let response = call(&state, get("/v1/stream?exclude_scope=private")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        state.ingest_batch(batch(
            1,
            vec![
                outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO),
                flow(
                    FlowDirection::Inbound,
                    ("192.168.1.24", 52_144),
                    ("10.0.0.2", 443),
                    5,
                    500,
                    Duration::ZERO,
                ),
            ],
        ));

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: tick"), "frame: {frame}");
        assert!(frame.contains("1.1.1.1"), "frame: {frame}");
        assert!(!frame.contains("192.168.1.24"), "frame: {frame}");
    }

    #[tokio::test]
    async fn flow_details_use_stable_ids() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO)],
        ));

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        let id = body["items"][0]["id"].as_str().expect("flow id").to_owned();

        let response = call(&state, get(&format!("/v1/flows/{id}"))).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["id"], id);
        assert_eq!(body["source"]["address"], "10.0.0.2");
        assert_eq!(body["interface"], "eth0");

        let response = call(&state, get("/v1/flows/00000000000000ff")).await;
        assert_problem(&response, StatusCode::NOT_FOUND);

        let response = call(&state, get("/v1/flows/not-hex")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn observations_produce_domains_endpoints_and_links() {
        let state = state();
        let mut batch = batch(
            1,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::from_secs(1)),
                outbound(("8.8.8.8", 53), 5, 500, Duration::from_secs(2)),
            ],
        );
        batch.domains = vec![observation(
            "Example.COM.",
            "93.184.216.34",
            DomainEvidence::Dns,
            AssociationConfidence::Inferred,
        )];
        state.ingest_batch(batch);

        let body = body_json(call(&state, get("/v1/domains")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domain"], "example.com");
        assert_eq!(body["items"][0]["evidence"][0], "dns");

        let body = body_json(call(&state, get("/v1/domains/example.com")).await).await;
        assert_eq!(body["addresses"][0]["address"], "93.184.216.34");
        assert!(
            body["addresses"][0]["first_seen"]
                .as_i64()
                .expect("first_seen")
                > 0
        );
        assert_eq!(body["flows_url"], "/v1/flows?domain=example.com");

        let body = body_json(call(&state, get("/v1/flows?domain=example.com")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domains"][0]["confidence"], "inferred");

        let body = body_json(call(&state, get("/v1/endpoints/93.184.216.34")).await).await;
        assert_eq!(body["ports"][0]["port"], 443);
        assert_eq!(body["flows_url"], "/v1/flows?ip=93.184.216.34");
        assert_eq!(body["profile"]["scope"], "public");
        assert_eq!(body["domains"][0]["domain"], "example.com");
    }

    fn timeline_bytes(body: &serde_json::Value, direction: &str) -> i64 {
        body["points"]
            .as_array()
            .expect("points")
            .iter()
            .map(|point| point[direction]["bytes"].as_i64().expect("bytes"))
            .sum()
    }

    #[tokio::test]
    async fn entity_timelines_follow_flow_deltas() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO),
                outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO),
            ],
        );
        incoming.domains = vec![observation(
            "example.com",
            "93.184.216.34",
            DomainEvidence::Dns,
            AssociationConfidence::Inferred,
        )];
        state.ingest_batch(incoming);

        let response = call(
            &state,
            get("/v1/endpoints/93.184.216.34/timeline?range=15m"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["resolution"], "minute");
        assert_eq!(timeline_bytes(&body, "outbound"), 4_000);
        assert_eq!(timeline_bytes(&body, "inbound"), 0);

        let body =
            body_json(call(&state, get("/v1/domains/example.com/timeline?range=15m")).await).await;
        assert_eq!(timeline_bytes(&body, "outbound"), 4_000);

        let body =
            body_json(call(&state, get("/v1/endpoints/8.8.8.8/timeline?range=15m")).await).await;
        assert_eq!(timeline_bytes(&body, "outbound"), 500);

        let response = call(&state, get("/v1/endpoints/not-an-ip/timeline")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn applications_aggregate_flow_traffic_and_domains() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO)],
        );
        incoming.flows[0].application = Some(ApplicationRef {
            tgid: 4242,
            uid: 1000,
            cgroup_id: 0,
            comm: "curl".into(),
        });
        incoming.domains = vec![observation(
            "example.com",
            "93.184.216.34",
            DomainEvidence::TlsSni,
            AssociationConfidence::Direct,
        )];
        state.ingest_batch(incoming);

        let body = body_json(call(&state, get("/v1/applications")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["id"], "proc:comm:curl");
        assert_eq!(body["items"][0]["name"], "curl");
        assert_eq!(body["items"][0]["kind"], "process");
        assert_eq!(body["items"][0]["traffic"]["outbound"]["bytes"], 4_000);
        assert_eq!(body["items"][0]["flow_count"], 1);

        let body = body_json(call(&state, get("/v1/applications/proc:comm:curl")).await).await;
        assert_eq!(body["domains"][0]["domain"], "example.com");
        assert_eq!(body["destinations"][0]["address"], "93.184.216.34");
        assert_eq!(
            body["destinations"][0]["domains"][0]["domain"],
            "example.com"
        );
        assert_eq!(
            body["destinations"][0]["traffic"]["outbound"]["bytes"],
            4_000
        );
        assert_eq!(body["destinations"][0]["flow_count"], 1);
        assert_eq!(
            body["flows_url"],
            "/v1/flows?application_id=proc%3Acomm%3Acurl"
        );

        let body = body_json(
            call(
                &state,
                get("/v1/applications/proc:comm:curl/timeline?range=15m"),
            )
            .await,
        )
        .await;
        assert_eq!(timeline_bytes(&body, "outbound"), 4_000);

        let body =
            body_json(call(&state, get("/v1/flows?application_id=proc:comm:curl")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["application"]["name"], "curl");

        let body = body_json(call(&state, get("/v1/flows?application_id=proc:other")).await).await;
        assert_eq!(body["total"], 0);

        let response = call(&state, get("/v1/applications/proc:missing")).await;
        assert_problem(&response, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn entities_report_interval_rates() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO)],
        );
        incoming.flows[0].application = Some(ApplicationRef {
            tgid: 4242,
            uid: 1000,
            cgroup_id: 0,
            comm: "curl".into(),
        });
        incoming.domains = vec![observation(
            "example.com",
            "93.184.216.34",
            DomainEvidence::TlsSni,
            AssociationConfidence::Direct,
        )];
        state.ingest_batch(incoming);

        // 4_000 bytes over a one-second interval is 32_000 bits per second.
        let body = body_json(call(&state, get("/v1/flows")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 32_000);
        assert_eq!(body["items"][0]["inbound_bps"], 0);

        let body = body_json(call(&state, get("/v1/endpoints")).await).await;
        assert_eq!(body["items"][0]["address"], "93.184.216.34");
        assert_eq!(body["items"][0]["outbound_bps"], 32_000);
        assert_eq!(body["items"][0]["inbound_bps"], 0);

        let body = body_json(call(&state, get("/v1/domains")).await).await;
        assert_eq!(body["items"][0]["domain"], "example.com");
        assert_eq!(body["items"][0]["outbound_bps"], 32_000);

        let body = body_json(call(&state, get("/v1/applications")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 32_000);
        assert_eq!(body["items"][0]["inbound_bps"], 0);

        let body = body_json(call(&state, get("/v1/connections")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 32_000);
        assert_eq!(body["items"][0]["inbound_bps"], 0);

        // Rates describe the latest interval only; idle intervals reset them.
        state.ingest_batch(batch(2, Vec::new()));
        let body = body_json(call(&state, get("/v1/flows")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 0);
        let body = body_json(call(&state, get("/v1/endpoints")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 0);
        let body = body_json(call(&state, get("/v1/domains")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 0);
        let body = body_json(call(&state, get("/v1/applications")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 0);
        let body = body_json(call(&state, get("/v1/connections")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 0);
    }

    #[tokio::test]
    async fn entities_sort_by_latest_interval_rate() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO),
                outbound(("198.51.100.7", 80), 40, 400_000, Duration::ZERO),
            ],
        );
        incoming.domains = vec![
            observation(
                "slow.example",
                "93.184.216.34",
                DomainEvidence::TlsSni,
                AssociationConfidence::Direct,
            ),
            observation(
                "fast.example",
                "198.51.100.7",
                DomainEvidence::TlsSni,
                AssociationConfidence::Direct,
            ),
        ];
        state.ingest_batch(incoming);

        // 400_000 B/s = 3_200_000 bps, 4_000 B/s = 32_000 bps.
        let body = body_json(call(&state, get("/v1/endpoints?sort=-rate")).await).await;
        assert_eq!(body["items"][0]["address"], "198.51.100.7");
        assert_eq!(body["items"][0]["outbound_bps"], 3_200_000);
        assert_eq!(body["items"][1]["address"], "93.184.216.34");

        let body = body_json(call(&state, get("/v1/endpoints?sort=-out_rate")).await).await;
        assert_eq!(body["items"][0]["address"], "198.51.100.7");
        let body = body_json(call(&state, get("/v1/endpoints?sort=out_rate")).await).await;
        assert_eq!(body["items"][0]["address"], "93.184.216.34");

        let body = body_json(call(&state, get("/v1/connections?sort=-rate")).await).await;
        assert_eq!(body["items"][0]["remote"]["address"], "198.51.100.7");

        let body = body_json(call(&state, get("/v1/flows?sort=-rate")).await).await;
        assert_eq!(body["items"][0]["remote"]["address"], "198.51.100.7");

        let body = body_json(call(&state, get("/v1/domains?sort=-rate")).await).await;
        assert_eq!(body["items"][0]["domain"], "fast.example");

        // Rates reset with the interval, so ordering falls back to zero.
        state.ingest_batch(batch(2, Vec::new()));
        let body = body_json(call(&state, get("/v1/endpoints?sort=-rate")).await).await;
        assert_eq!(body["items"][0]["outbound_bps"], 0);
    }

    #[tokio::test]
    async fn flow_filters_cover_service_scope_and_absolute_time() {
        let state = state();
        let incoming = batch(
            1,
            vec![
                {
                    let mut update = outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO);
                    update.service = Some("TLS".into());
                    update
                },
                {
                    let mut update = outbound(("192.168.1.10", 22), 40, 4_000, Duration::ZERO);
                    update.service = Some("SSH".into());
                    update
                },
                // The server side of the SSH pair carries no fingerprint: the
                // connection filter must keep its totals, not drop the row.
                flow(
                    FlowDirection::Inbound,
                    ("192.168.1.10", 22),
                    ("10.0.0.2", 40_000),
                    30,
                    9_000,
                    Duration::ZERO,
                ),
            ],
        );
        state.ingest_batch(incoming);

        // Service filter on directional flows.
        let body = body_json(call(&state, get("/v1/flows?service=SSH")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "192.168.1.10");

        // Service filter on connections applies after aggregation, so the
        // unfingerprinted direction still contributes its bytes.
        let body = body_json(call(&state, get("/v1/connections?service=SSH")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "192.168.1.10");
        assert_eq!(body["items"][0]["traffic"]["inbound"]["bytes"], 9_000);
        assert_eq!(body["items"][0]["traffic"]["outbound"]["bytes"], 4_000);

        // Search matches the fingerprint service name too.
        let body = body_json(call(&state, get("/v1/flows?q=ssh")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "192.168.1.10");

        // Scope lists: the LAN shorthand and a single public scope.
        let body = body_json(
            call(
                &state,
                get("/v1/flows?scope=private,link_local,unique_local,loopback"),
            )
            .await,
        )
        .await;
        assert_eq!(body["total"], 2);
        let body = body_json(call(&state, get("/v1/flows?scope=public")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "93.184.216.34");

        // Absolute time windows.
        let now = unix_millis(SystemTime::now());
        let body = body_json(
            call(
                &state,
                get(&format!(
                    "/v1/flows?start={}&end={}",
                    now - 60_000,
                    now + 60_000
                )),
            )
            .await,
        )
        .await;
        assert_eq!(body["total"], 3);
        let body = body_json(call(&state, get("/v1/flows?start=1&end=2")).await).await;
        assert_eq!(body["total"], 0);

        // start/end validation: pairing, ordering, and range exclusivity.
        for uri in [
            "/v1/flows?start=1".to_owned(),
            "/v1/flows?end=2".to_owned(),
            "/v1/flows?start=2&end=1".to_owned(),
            "/v1/flows?range=15m&start=1&end=2".to_owned(),
        ] {
            let response = call(&state, get(&uri)).await;
            assert_problem(&response, StatusCode::UNPROCESSABLE_ENTITY);
        }

        // Fingerprint service names ride /v1/status for the filter dropdown.
        let status = body_json(call(&state, get("/v1/status")).await).await;
        let services: Vec<String> = status["fingerprints"]["services"]
            .as_array()
            .expect("services")
            .iter()
            .map(|service| service.as_str().expect("service name").to_owned())
            .collect();
        assert!(services.iter().any(|service| service == "SSH"));
        assert!(services.iter().any(|service| service == "TLS"));
        let mut sorted = services.clone();
        sorted.sort();
        assert_eq!(sorted, services);
    }

    #[tokio::test]
    async fn tick_carries_touched_application_summaries() {
        let state = state();
        let response = call(&state, get("/v1/stream")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        let mut incoming = batch(
            1,
            vec![outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO)],
        );
        incoming.flows[0].application = Some(ApplicationRef {
            tgid: 4242,
            uid: 0,
            cgroup_id: 0,
            comm: "wget".into(),
        });
        state.ingest_batch(incoming);

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: tick"), "frame: {frame}");
        assert!(frame.contains("proc:comm:wget"), "frame: {frame}");
    }

    #[tokio::test]
    async fn overview_aggregates_traffic_and_visibility() {
        let state = state();
        let mut batch = batch(
            1,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO),
                outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO),
            ],
        );
        batch.domains = vec![observation(
            "example.com",
            "93.184.216.34",
            DomainEvidence::TlsSni,
            AssociationConfidence::Direct,
        )];
        state.ingest_batch(batch);

        let body = body_json(call(&state, get("/v1/overview?range=15m")).await).await;
        assert_eq!(body["range"], "15m");
        assert_eq!(body["totals"]["outbound"]["bytes"], 4_500);
        assert_eq!(body["active_flows"], 2);
        assert_eq!(body["domain_visibility"]["flows_with_domain"], 1);
        assert_eq!(body["domain_visibility"]["flows_total"], 2);
        assert_eq!(
            body["domain_visibility"]["by_evidence"][0]["evidence"],
            "tls_sni"
        );
        assert_eq!(body["domain_visibility"]["by_evidence"][0]["flows"], 1);
        assert_eq!(body["top_endpoints"][0]["address"], "93.184.216.34");
        assert_eq!(body["top_domains"][0]["domain"], "example.com");
        assert!(body["timeline"]["points"].as_array().expect("points").len() >= 15);
    }

    #[tokio::test]
    async fn overview_reports_proxied_fake_ip_traffic() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![flow(
                FlowDirection::Inbound,
                ("198.18.0.5", 443),
                ("10.0.0.2", 40_000),
                10,
                1_000,
                Duration::ZERO,
            )],
        );
        incoming.domains = vec![observation(
            "example.com",
            "198.18.0.5",
            DomainEvidence::Dns,
            AssociationConfidence::Inferred,
        )];
        state.ingest_batch(incoming);

        let body = body_json(call(&state, get("/v1/overview?range=15m")).await).await;
        assert_eq!(body["proxied"]["flows"], 1);
        assert_eq!(body["proxied"]["bytes"], 1_000);
        assert_eq!(body["proxied"]["flows_with_domain"], 1);
        // Fake IPs are never attributed to a country.
        assert_eq!(
            body["top_countries"].as_array().expect("countries").len(),
            0
        );
    }

    #[tokio::test]
    async fn proxy_resolution_enriches_fake_ip_flows() {
        let state = state();
        state
            .lock()
            .db
            .set_geoip_database(crate::enrichment::database::test_database());
        state.lock().proxy.insert_resolution(
            crate::proxy::ProxyKey {
                client: "10.0.0.2".parse().expect("client"),
                client_port: 40_000,
                destination_port: 443,
            },
            crate::proxy::ProxyResolution {
                real_address: Some("8.8.8.8".parse().expect("real")),
                host: Some("github.com".to_owned()),
                ..crate::proxy::ProxyResolution::default()
            },
        );

        state.ingest_batch(batch(
            1,
            vec![outbound(("198.18.0.27", 443), 10, 1_000, Duration::ZERO)],
        ));

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        let profile = &body["items"][0]["remote_profile"];
        assert_eq!(profile["scope"], "fake_ip");
        assert_eq!(profile["country"], "US");
        assert_eq!(profile["asn"], 15169);

        let body = body_json(call(&state, get("/v1/overview?range=15m")).await).await;
        assert_eq!(body["top_countries"][0]["country"], "US");
        assert_eq!(body["proxied"]["resolved_flows"], 1);

        let status = body_json(call(&state, get("/v1/status")).await).await;
        assert_eq!(status["proxy"]["enabled"], false);
    }

    #[tokio::test]
    async fn fake_ip_enrichment_survives_unresolved_ticks() {
        let state = state();
        state
            .lock()
            .db
            .set_geoip_database(crate::enrichment::database::test_database());
        state.lock().proxy.insert_resolution(
            crate::proxy::ProxyKey {
                client: "10.0.0.2".parse().expect("client"),
                client_port: 40_000,
                destination_port: 443,
            },
            crate::proxy::ProxyResolution {
                real_address: Some("8.8.8.8".parse().expect("real")),
                ..crate::proxy::ProxyResolution::default()
            },
        );

        state.ingest_batch(batch(
            1,
            vec![outbound(("198.18.0.27", 443), 10, 1_000, Duration::ZERO)],
        ));

        // The proxy mapping disappears (poll gap, restart, disabled): later
        // ticks must not wipe the attribution already stored.
        state.lock().proxy.configure(false, "", "");
        state.ingest_batch(batch(
            2,
            vec![outbound(
                ("198.18.0.27", 443),
                20,
                2_000,
                Duration::from_secs(1),
            )],
        ));

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        let profile = &body["items"][0]["remote_profile"];
        assert_eq!(profile["scope"], "fake_ip");
        assert_eq!(profile["country"], "US");
        assert_eq!(profile["asn"], 15169);
    }

    #[tokio::test]
    async fn settings_validate_normalize_and_persist() {
        let state = state();

        let response = call(&state, get("/v1/settings")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["history"]["retention_days"], 7);

        let response = call(
            &state,
            json_request(
                Method::PATCH,
                "/v1/settings",
                serde_json::json!({ "history": { "retention_days": 5 } }),
            ),
        )
        .await;
        assert_problem(&response, StatusCode::UNPROCESSABLE_ENTITY);

        let response = call(
            &state,
            json_request(
                Method::PATCH,
                "/v1/settings",
                serde_json::json!({
                    "history": { "retention_days": 30 },
                    "domains": { "enabled": false, "tls_sni": true }
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["history"]["retention_days"], 30);
        assert_eq!(body["domains"]["enabled"], false);
        assert_eq!(body["domains"]["tls_sni"], false);

        let body = body_json(call(&state, get("/v1/settings")).await).await;
        assert_eq!(body["history"]["retention_days"], 30);

        let response = call(
            &state,
            json_request(Method::PUT, "/v1/settings", serde_json::json!({})),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["history"]["retention_days"], 7);
    }

    #[tokio::test]
    async fn exports_are_created_downloaded_and_deleted() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO)],
        ));

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/exports",
                serde_json::json!({ "format": "csv", "range": "15m" }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("/v1/exports/exp-"))
        );
        let body = body_json(response).await;
        assert_eq!(body["record_count"], 1);
        assert_eq!(body["range"], "15m");
        let download_url = body["download_url"]
            .as_str()
            .expect("download url")
            .to_owned();

        let body = body_json(call(&state, get("/v1/exports")).await).await;
        assert_eq!(body.as_array().expect("exports").len(), 1);

        let response = call(&state, get(&download_url)).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/csv")
        );
        let csv = body_text(response).await;
        assert!(csv.starts_with(CSV_TEST_PREFIX));
        assert!(csv.contains("1.1.1.1"));

        let resource = download_url.trim_end_matches("/content").to_owned();
        let response = call(
            &state,
            Request::builder()
                .method(Method::DELETE)
                .uri(&resource)
                .body(Body::empty())
                .expect("valid request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = call(&state, get(&download_url)).await;
        assert_problem(&response, StatusCode::NOT_FOUND);
    }

    const CSV_TEST_PREFIX: &str = "id,direction,protocol,state,end_reason,src_ip";

    #[tokio::test]
    async fn expired_export_content_is_gone() {
        let state = state_with_export_ttl(Duration::ZERO);
        state.ingest_batch(batch(
            1,
            vec![outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO)],
        ));

        let response = call(
            &state,
            json_request(Method::POST, "/v1/exports", serde_json::json!({})),
        )
        .await;
        let body = body_json(response).await;
        assert_eq!(body["status"], "expired");
        let download_url = body["download_url"].as_str().expect("download url");

        let response = call(&state, get(download_url)).await;
        assert_problem(&response, StatusCode::GONE);
    }

    #[tokio::test]
    async fn clearing_history_requires_confirmation() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO)],
        ));

        let response = call(
            &state,
            Request::builder()
                .method(Method::DELETE)
                .uri("/v1/history")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await;
        assert_problem(&response, StatusCode::PRECONDITION_REQUIRED);

        let response = call(
            &state,
            Request::builder()
                .method(Method::DELETE)
                .uri("/v1/history?confirm=true")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        assert_eq!(body["total"], 0);
        let body = body_json(call(&state, get("/v1/domains")).await).await;
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn endpoints_list_supports_scope_and_sort() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![
                outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO),
                outbound(("1.1.1.1", 443), 50, 5_000, Duration::ZERO),
            ],
        ));

        let body = body_json(call(&state, get("/v1/endpoints?sort=-bytes")).await).await;
        assert_eq!(body["items"][0]["address"], "1.1.1.1");
        assert_eq!(body["items"][1]["address"], "8.8.8.8");

        let body = body_json(call(&state, get("/v1/endpoints?scope=public&limit=1")).await).await;
        assert_eq!(body["total"], 2);
        assert_eq!(body["items"].as_array().expect("items").len(), 1);

        let body = body_json(call(&state, get("/v1/endpoints?scope=loopback")).await).await;
        assert_eq!(body["total"], 0);

        let body = body_json(call(&state, get("/v1/endpoints?sort=address")).await).await;
        assert_eq!(body["items"][0]["address"], "1.1.1.1");
        // Both fixture flows are outbound, so inbound bytes tie at zero.
        let body = body_json(call(&state, get("/v1/endpoints?sort=-in_bytes")).await).await;
        assert_eq!(body["total"], 2);
        let body = body_json(call(&state, get("/v1/endpoints?sort=-organization")).await).await;
        assert_eq!(body["total"], 2);

        let response = call(&state, get("/v1/endpoints?sort=-mystery")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn summaries_split_traffic_by_direction() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("9.9.9.9", 443), 10, 1_000, Duration::ZERO),
                flow(
                    FlowDirection::Inbound,
                    ("9.9.9.9", 55_000),
                    ("10.0.0.2", 443),
                    30,
                    3_000,
                    Duration::ZERO,
                ),
            ],
        );
        incoming.domains = vec![observation(
            "example.com",
            "9.9.9.9",
            DomainEvidence::TlsSni,
            AssociationConfidence::Direct,
        )];
        state.ingest_batch(incoming);

        let body = body_json(call(&state, get("/v1/endpoints?q=9.9.9.9")).await).await;
        let endpoint = &body["items"][0];
        assert_eq!(endpoint["bytes"], 4_000);
        assert_eq!(endpoint["traffic"]["inbound"]["bytes"], 3_000);
        assert_eq!(endpoint["traffic"]["outbound"]["bytes"], 1_000);

        let body = body_json(call(&state, get("/v1/domains?q=example.com")).await).await;
        let domain = &body["items"][0];
        assert_eq!(domain["traffic"]["inbound"]["bytes"], 3_000);
        assert_eq!(domain["traffic"]["outbound"]["bytes"], 1_000);

        let body = body_json(call(&state, get("/v1/overview?range=15m")).await).await;
        assert_eq!(
            body["top_endpoints"][0]["traffic"]["inbound"]["bytes"],
            3_000
        );
        assert_eq!(
            body["top_endpoints"][0]["traffic"]["outbound"]["bytes"],
            1_000
        );
    }

    fn instant_flow(
        direction: FlowDirection,
        source: (&str, u16),
        destination: (&str, u16),
        bytes: u64,
    ) -> FlowUpdate {
        let now = Instant::now();
        FlowUpdate {
            key: FlowKey {
                source: Endpoint {
                    address: source.0.parse().expect("source address"),
                    port: Some(source.1),
                },
                destination: Endpoint {
                    address: destination.0.parse().expect("destination address"),
                    port: Some(destination.1),
                },
                interface_index: NonZeroU32::new(7).expect("non-zero ifindex"),
                protocol: Protocol::Tcp,
                direction,
            },
            delta: TrafficCounters { packets: 1, bytes },
            total: TrafficCounters { packets: 1, bytes },
            first_seen: now,
            last_seen: now,
            state: FlowState::Active,
            service: None,
            application: None,
        }
    }

    #[tokio::test]
    async fn connections_merge_directions_and_hide_noise() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO),
                flow(
                    FlowDirection::Inbound,
                    ("1.1.1.1", 443),
                    ("10.0.0.2", 40_000),
                    20,
                    2_000,
                    Duration::ZERO,
                ),
                flow_with(
                    Protocol::Udp,
                    FlowDirection::Outbound,
                    ("10.0.0.2", 41_235),
                    ("8.8.8.8", 53),
                    1,
                    100,
                    Duration::ZERO,
                ),
                flow_with(
                    Protocol::Udp,
                    FlowDirection::Inbound,
                    ("8.8.8.8", 53),
                    ("10.0.0.2", 41_235),
                    1,
                    120,
                    Duration::ZERO,
                ),
                instant_flow(
                    FlowDirection::Outbound,
                    ("10.0.0.2", 41_236),
                    ("9.9.9.9", 80),
                    64,
                ),
            ],
        );
        incoming.domains = vec![observation(
            "example.com",
            "9.9.9.9",
            DomainEvidence::TlsSni,
            AssociationConfidence::Direct,
        )];
        state.ingest_batch(incoming);

        // Without noise filtering: the TCP pair, the DNS pair and the
        // sub-second connection are all present.
        let body = body_json(call(&state, get("/v1/connections?range=15m")).await).await;
        assert_eq!(body["total"], 3);
        let items = body["items"].as_array().expect("items");
        let find = |address: &str| {
            items
                .iter()
                .find(|item| item["remote"]["address"] == address)
                .expect("connection present")
        };
        // No fingerprint was recorded for these flows, so the honest
        // fallback is NULL (the UI shows TCP/UDP); the TLS association on
        // 9.9.9.9 still names its protocol through Domain Evidence.
        assert!(find("1.1.1.1")["service"].is_null());
        assert!(find("8.8.8.8")["service"].is_null());
        assert_eq!(find("9.9.9.9")["service"], "TLS");

        let body =
            body_json(call(&state, get("/v1/connections?range=15m&hide_noise=true")).await).await;
        assert_eq!(body["total"], 1);
        let connection = &body["items"][0];
        assert_eq!(connection["remote"]["address"], "1.1.1.1");
        assert_eq!(connection["host"]["address"], "10.0.0.2");
        assert_eq!(connection["bytes"], 3_000);
        assert_eq!(connection["packets"], 30);
        assert_eq!(connection["traffic"]["inbound"]["bytes"], 2_000);
        assert_eq!(connection["traffic"]["outbound"]["bytes"], 1_000);
        assert_eq!(connection["state"], "active");
        assert_eq!(connection["id"].as_str().expect("id").len(), 16);

        let body = body_json(call(&state, get("/v1/connections?state=ended")).await).await;
        assert_eq!(body["total"], 0);

        let body = body_json(call(&state, get("/v1/connections?sort=-bytes")).await).await;
        assert_eq!(body["total"], 3);
        assert_eq!(body["items"][0]["remote"]["address"], "1.1.1.1");

        // Column-level sorts: inbound bytes, service and peer address.
        let body = body_json(call(&state, get("/v1/connections?sort=-in_bytes")).await).await;
        assert_eq!(body["items"][0]["remote"]["address"], "1.1.1.1");
        let body = body_json(call(&state, get("/v1/connections?sort=service")).await).await;
        assert_eq!(body["total"], 3);
        let body = body_json(call(&state, get("/v1/connections?sort=remote")).await).await;
        assert_eq!(body["total"], 3);
        let body = body_json(call(&state, get("/v1/connections?sort=domain")).await).await;
        assert_eq!(body["total"], 3);
        let body = body_json(call(&state, get("/v1/flows?sort=domain")).await).await;
        assert_eq!(body["total"], 5);

        let response = call(&state, get("/v1/connections?sort=-mystery")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn connections_expose_fingerprinted_service() {
        let state = state();
        let mut update = outbound(("1.1.1.1", 22), 10, 1_000, Duration::ZERO);
        update.service = Some("SSH".into());
        state.ingest_batch(batch(1, vec![update]));

        let body = body_json(call(&state, get("/v1/connections")).await).await;
        assert_eq!(body["items"][0]["service"], "SSH");

        let status = body_json(call(&state, get("/v1/status")).await).await;
        assert!(status["fingerprints"]["rules"].as_u64().expect("rules") > 0);
    }

    #[tokio::test]
    async fn fingerprints_can_be_read_replaced_and_reset() {
        let state = state();

        let response = call(&state, get("/v1/fingerprints")).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            body_text(response).await.contains("\"SSH\""),
            "default library is served"
        );

        let custom = serde_json::json!({
            "rules": [{
                "service": "SOCKS5",
                "match": [{ "op": "byte", "offset": 0, "compare": { "eq": 5 } }]
            }]
        });
        let response = call(
            &state,
            json_request(Method::PUT, "/v1/fingerprints", custom),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let response = call(&state, get("/v1/fingerprints")).await;
        let text = body_text(response).await;
        assert!(text.contains("SOCKS5"));
        assert!(!text.contains("\"SSH\""));

        let response = call(
            &state,
            json_request(
                Method::PUT,
                "/v1/fingerprints",
                serde_json::json!({ "rules": [] }),
            ),
        )
        .await;
        assert_problem(&response, StatusCode::UNPROCESSABLE_ENTITY);

        let response = call(
            &state,
            Request::builder()
                .method(Method::DELETE)
                .uri("/v1/fingerprints")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = call(&state, get("/v1/fingerprints")).await;
        assert!(body_text(response).await.contains("\"SSH\""));
    }

    #[tokio::test]
    async fn endpoint_address_sort_is_numeric() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![
                outbound(("192.168.1.1", 445), 1, 100, Duration::ZERO),
                outbound(("10.0.0.1", 443), 1, 100, Duration::ZERO),
                outbound(("2.2.2.2", 443), 1, 100, Duration::ZERO),
            ],
        ));

        let body = body_json(call(&state, get("/v1/endpoints?sort=address")).await).await;
        let addresses: Vec<&str> = body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["address"].as_str().expect("address"))
            .collect();
        assert_eq!(addresses, ["2.2.2.2", "10.0.0.1", "192.168.1.1"]);

        let body = body_json(call(&state, get("/v1/endpoints?sort=-address")).await).await;
        let addresses: Vec<&str> = body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["address"].as_str().expect("address"))
            .collect();
        assert_eq!(addresses, ["192.168.1.1", "10.0.0.1", "2.2.2.2"]);

        // The same helper backs Flow and connection peer ordering.
        let body = body_json(call(&state, get("/v1/flows?sort=remote")).await).await;
        assert_eq!(body["total"], 3);
        let body = body_json(call(&state, get("/v1/connections?sort=remote")).await).await;
        assert_eq!(body["total"], 3);
    }

    #[tokio::test]
    async fn domain_sort_follows_dns_hierarchy() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("1.1.1.1", 443), 1, 100, Duration::ZERO),
                outbound(("2.2.2.2", 443), 1, 100, Duration::ZERO),
                outbound(("3.3.3.3", 443), 1, 100, Duration::ZERO),
            ],
        );
        incoming.domains = vec![
            observation(
                "api.example.com",
                "1.1.1.1",
                DomainEvidence::TlsSni,
                AssociationConfidence::Direct,
            ),
            observation(
                "example.com",
                "2.2.2.2",
                DomainEvidence::TlsSni,
                AssociationConfidence::Direct,
            ),
            observation(
                "a.other.com",
                "3.3.3.3",
                DomainEvidence::TlsSni,
                AssociationConfidence::Direct,
            ),
        ];
        state.ingest_batch(incoming);

        // Parent domains sort before their own subdomains and TLDs group.
        let body = body_json(call(&state, get("/v1/domains?sort=domain")).await).await;
        let domains: Vec<&str> = body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["domain"].as_str().expect("domain"))
            .collect();
        assert_eq!(domains, ["example.com", "api.example.com", "a.other.com"]);

        let body = body_json(call(&state, get("/v1/domains?sort=-domain")).await).await;
        let domains: Vec<&str> = body["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["domain"].as_str().expect("domain"))
            .collect();
        assert_eq!(domains, ["a.other.com", "api.example.com", "example.com"]);
    }

    #[tokio::test]
    async fn endpoint_profile_uses_the_geoip_database() {
        let state = state();
        state
            .lock()
            .db
            .set_geoip_database(crate::enrichment::database::test_database());
        state.ingest_batch(batch(
            1,
            vec![outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO)],
        ));

        let body = body_json(call(&state, get("/v1/endpoints/8.8.8.8")).await).await;
        assert_eq!(body["profile"]["country"], "US");
        assert_eq!(body["profile"]["region"], "California");
        assert_eq!(body["profile"]["city_approximate"], "Mountain View");
        assert_eq!(body["profile"]["asn"], 15169);
        assert_eq!(body["profile"]["organization"], "Google LLC");

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        assert_eq!(body["items"][0]["remote_profile"]["country"], "US");
        assert_eq!(body["items"][0]["remote_profile"]["asn"], 15169);

        let body = body_json(call(&state, get("/v1/overview?range=15m")).await).await;
        assert_eq!(body["top_countries"][0]["country"], "US");
        assert_eq!(body["top_asns"][0]["asn"], 15169);
    }

    #[tokio::test]
    async fn geoip_backfill_enriches_stored_public_addresses() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO)],
        ));

        let body = body_json(call(&state, get("/v1/endpoints/8.8.8.8")).await).await;
        assert!(body["profile"]["country"].is_null());

        state
            .lock()
            .db
            .set_geoip_database(crate::enrichment::database::test_database());
        assert_eq!(state.lock().db.backfill_enrichment().expect("backfill"), 1);

        let body = body_json(call(&state, get("/v1/endpoints/8.8.8.8")).await).await;
        assert_eq!(body["profile"]["country"], "US");
        assert_eq!(body["profile"]["asn"], 15169);

        let body = body_json(call(&state, get("/v1/flows")).await).await;
        assert_eq!(body["items"][0]["remote_profile"]["country"], "US");
    }

    async fn next_frame(body: &mut Body) -> String {
        let frame = tokio::time::timeout(Duration::from_secs(5), body.frame())
            .await
            .expect("frame arrives")
            .expect("stream stays open")
            .expect("frame is valid");
        String::from_utf8(frame.into_data().expect("data frame").to_vec()).expect("UTF-8 frame")
    }

    fn assert_event_stream(response: &Response) {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/event-stream")
        );
    }

    #[tokio::test]
    async fn stream_pushes_filtered_tick_events() {
        let state = state();
        let response = call(&state, get("/v1/stream?direction=inbound")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        state.ingest_batch(batch(
            7,
            vec![
                outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO),
                flow(
                    FlowDirection::Inbound,
                    ("9.9.9.9", 55_000),
                    ("10.0.0.2", 443),
                    30,
                    3_000,
                    Duration::ZERO,
                ),
            ],
        ));

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: tick"), "frame: {frame}");
        assert!(frame.contains("id: 7"), "frame: {frame}");
        assert!(frame.contains("9.9.9.9"), "frame: {frame}");
        assert!(!frame.contains("1.1.1.1"), "frame: {frame}");
        assert!(frame.contains("\"inbound_bps\":"), "frame: {frame}");
        assert!(frame.contains("\"inbound_bps\":24000"), "frame: {frame}");
        assert!(frame.contains("\"health\":"), "frame: {frame}");
        assert!(frame.contains("\"remote_profile\":"), "frame: {frame}");
        assert!(frame.contains("\"scope\":\"public\""), "frame: {frame}");
        assert!(frame.contains("\"observations\":"), "frame: {frame}");
        assert!(frame.contains("\"active_flows\":2"), "frame: {frame}");
        assert!(frame.contains("\"flows_total\":2"), "frame: {frame}");
    }

    #[tokio::test]
    async fn stream_conveys_domain_observations() {
        let state = state();
        let response = call(&state, get("/v1/stream?domain=example.com")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        let mut incoming = batch(
            1,
            vec![outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO)],
        );
        incoming.domains = vec![observation(
            "Example.COM.",
            "93.184.216.34",
            DomainEvidence::Dns,
            AssociationConfidence::Inferred,
        )];
        state.ingest_batch(incoming);

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: tick"), "frame: {frame}");
        assert!(
            frame.contains("\"domain\":\"example.com\""),
            "frame: {frame}"
        );
        assert!(frame.contains("93.184.216.34"), "frame: {frame}");
    }

    #[tokio::test]
    async fn tick_carries_touched_endpoint_and_domain_aggregates() {
        let state = state();
        let response = call(&state, get("/v1/stream")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        // Aggregates ride every third interval; sequence 4 is one of them.
        let mut incoming = batch(
            4,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO),
                outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO),
            ],
        );
        incoming.domains = vec![observation(
            "example.com",
            "93.184.216.34",
            DomainEvidence::TlsSni,
            AssociationConfidence::Direct,
        )];
        state.ingest_batch(incoming);

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: tick"), "frame: {frame}");
        let payload = frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .expect("data line");
        let tick: serde_json::Value = serde_json::from_str(payload).expect("tick JSON");

        let endpoints = tick["endpoints"].as_array().expect("endpoints");
        assert_eq!(endpoints.len(), 2);
        let example = endpoints
            .iter()
            .find(|endpoint| endpoint["address"] == "93.184.216.34")
            .expect("touched endpoint");
        assert_eq!(example["bytes"], 4_000);
        assert_eq!(example["flow_count"], 1);

        let domains = tick["domains"].as_array().expect("domains");
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0]["domain"], "example.com");
        assert_eq!(domains[0]["bytes"], 4_000);
        assert_eq!(domains[0]["evidence"][0], "tls_sni");

        let observations = tick["observations"].as_array().expect("observations");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0]["address"], "93.184.216.34");

        assert_eq!(tick["overview"]["active_flows"], 2);
        assert_eq!(tick["overview"]["flows_with_domain"], 1);
        assert_eq!(tick["overview"]["flows_total"], 2);
    }

    #[tokio::test]
    async fn stream_resyncs_lagging_subscribers() {
        let state = state();
        let response = call(&state, get("/v1/stream")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        for sequence in 0..(STREAM_CHANNEL_CAPACITY + 8) {
            state.ingest_batch(batch(sequence as u64, vec![]));
        }

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: resync"), "frame: {frame}");
    }

    #[tokio::test]
    async fn last_event_id_forces_a_resync() {
        let state = state();
        let request = Request::builder()
            .uri("/v1/stream")
            .header("last-event-id", "41")
            .body(Body::empty())
            .expect("valid request");
        let response = call(&state, request).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: resync"), "frame: {frame}");
        assert!(frame.contains("reconnected"), "frame: {frame}");
    }

    #[tokio::test]
    async fn stream_rejects_unsupported_filters() {
        let response = call(&state(), get("/v1/stream?country=US")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn generic_search_spans_flows_endpoints_domains_and_exports() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO),
                flow_with(
                    Protocol::Udp,
                    FlowDirection::Outbound,
                    ("10.0.0.2", 40_000),
                    ("8.8.8.8", 53),
                    5,
                    500,
                    Duration::ZERO,
                ),
            ],
        );
        incoming.domains = vec![observation(
            "Example.COM.",
            "93.184.216.34",
            DomainEvidence::Dns,
            AssociationConfidence::Inferred,
        )];
        state.ingest_batch(incoming);

        let body = body_json(call(&state, get("/v1/flows?q=UDP")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "8.8.8.8");

        let body = body_json(call(&state, get("/v1/flows?q=93.184")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["remote"]["address"], "93.184.216.34");

        let body = body_json(call(&state, get("/v1/flows?q=EXAMPLE")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domains"][0]["domain"], "example.com");

        let body = body_json(call(&state, get("/v1/domains?q=example")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domain"], "example.com");

        let body = body_json(call(&state, get("/v1/endpoints?q=93.184")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["address"], "93.184.216.34");

        let body = body_json(call(&state, get("/v1/flows?q=no-such-thing")).await).await;
        assert_eq!(body["total"], 0);

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/exports",
                serde_json::json!({ "format": "json", "q": "udp" }),
            ),
        )
        .await;
        let body = body_json(response).await;
        assert_eq!(body["record_count"], 1);
    }

    #[tokio::test]
    async fn domain_filters_apply_to_associations() {
        let state = state();
        let mut incoming = batch(
            1,
            vec![
                outbound(("93.184.216.34", 443), 40, 4_000, Duration::ZERO),
                outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO),
            ],
        );
        incoming.domains = vec![
            observation(
                "example.com",
                "93.184.216.34",
                DomainEvidence::Dns,
                AssociationConfidence::Inferred,
            ),
            observation(
                "cdn.example.net",
                "8.8.8.8",
                DomainEvidence::TlsSni,
                AssociationConfidence::Direct,
            ),
        ];
        state.ingest_batch(incoming);

        let body = body_json(call(&state, get("/v1/domains?evidence=dns")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domain"], "example.com");

        let body = body_json(call(&state, get("/v1/domains?confidence=direct")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["domain"], "cdn.example.net");

        // Canonical DNS order groups by TLD first: com before net.
        let body = body_json(call(&state, get("/v1/domains?sort=domain")).await).await;
        assert_eq!(body["items"][0]["domain"], "example.com");
    }

    #[tokio::test]
    async fn stream_applies_generic_search() {
        let state = state();
        let response = call(&state, get("/v1/stream?q=udp")).await;
        assert_event_stream(&response);
        let mut body = response.into_body();

        state.ingest_batch(batch(
            1,
            vec![
                outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO),
                flow_with(
                    Protocol::Udp,
                    FlowDirection::Outbound,
                    ("10.0.0.2", 40_000),
                    ("8.8.8.8", 53),
                    5,
                    500,
                    Duration::ZERO,
                ),
            ],
        ));

        let frame = next_frame(&mut body).await;
        assert!(frame.contains("event: tick"), "frame: {frame}");
        assert!(frame.contains("8.8.8.8"), "frame: {frame}");
        assert!(!frame.contains("1.1.1.1"), "frame: {frame}");
    }

    #[tokio::test]
    async fn router_with_ui_serves_the_spa_and_keeps_the_api() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("zimascope-ui-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create ui dir");
        std::fs::write(dir.join("index.html"), "<html>spa</html>").expect("write index");
        std::fs::write(dir.join("app.js"), "console.log('spa')").expect("write asset");

        let app = router_with_ui(state(), &dir);

        let response = app.clone().oneshot(get("/")).await.expect("index");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(body_text(response).await.contains("spa"));

        let response = app.clone().oneshot(get("/app.js")).await.expect("asset");
        assert_eq!(response.status(), StatusCode::OK);

        // Hash-routed deep links still boot the SPA.
        let response = app
            .clone()
            .oneshot(get("/explore"))
            .await
            .expect("deep link");
        assert!(body_text(response).await.contains("spa"));

        // The API stays JSON, including unknown paths.
        let response = app
            .clone()
            .oneshot(get("/v1/status"))
            .await
            .expect("status");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );

        let response = app.oneshot(get("/v1/nope")).await.expect("api 404");
        assert_problem(&response, StatusCode::NOT_FOUND);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn traffic_rules_crud_and_status() {
        let state = state();

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/traffic-rules",
                serde_json::json!({
                    "action": "limit",
                    "direction": "outbound",
                    "selector": { "kind": "endpoint", "address": "203.0.113.9", "port": 443 },
                    "rate_bytes_per_s": 12_500_000
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = body_json(response).await;
        assert_eq!(body["id"], 1);
        assert_eq!(body["action"], "limit");
        assert_eq!(body["direction"], "outbound");
        assert_eq!(body["selector"]["kind"], "endpoint");
        assert_eq!(body["selector"]["address"], "203.0.113.9");
        assert_eq!(body["selector"]["port"], 443);
        assert_eq!(body["rate_bytes_per_s"], 12_500_000);
        assert_eq!(body["burst_bytes"], 12_500_000);
        assert_eq!(body["enabled"], true);
        assert_eq!(body["state"], "unavailable");
        assert!(body["counters"].is_null());

        let body = body_json(call(&state, get("/v1/traffic-rules")).await).await;
        assert_eq!(body.as_array().expect("rules").len(), 1);

        let response = call(
            &state,
            json_request(
                Method::PATCH,
                "/v1/traffic-rules/1",
                serde_json::json!({ "enabled": false }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["enabled"], false);
        // No collector handle is attached in this test, so every rule is
        // reported as unavailable rather than pretending to be enforced.
        assert_eq!(body["state"], "unavailable");

        let response = call(
            &state,
            Request::builder()
                .method(Method::DELETE)
                .uri("/v1/traffic-rules/1")
                .body(Body::empty())
                .expect("valid request"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let body = body_json(call(&state, get("/v1/traffic-rules")).await).await;
        assert_eq!(body.as_array().expect("rules").len(), 0);

        let status = body_json(call(&state, get("/v1/status")).await).await;
        assert_eq!(status["enforcement"]["enabled"], true);
        assert_eq!(status["enforcement"]["available"], false);
        assert_eq!(status["enforcement"]["rules_total"], 0);
        assert!(
            status["recent_operations"]
                .as_array()
                .expect("operations")
                .iter()
                .any(|operation| operation["action"] == "traffic_rule.create")
        );
    }

    #[tokio::test]
    async fn traffic_rule_requests_are_validated() {
        let state = state();
        let invalid = [
            serde_json::json!({
                "action": "nope",
                "direction": "outbound",
                "selector": { "kind": "endpoint", "address": "203.0.113.9" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "selector": { "kind": "endpoint", "address": "203.0.113.9" },
                "rate_bytes_per_s": 1
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "selector": { "kind": "cidr", "address": "192.0.2.0" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "selector": { "kind": "application", "id": "  " },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "block",
                "direction": "outbound",
                "selector": { "kind": "endpoint", "address": "203.0.113.9" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "sideways",
                "selector": { "kind": "endpoint", "address": "203.0.113.9" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "selector": { "kind": "domain", "domain": "example.com" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "selector": { "kind": "endpoint", "address": "2001:db8::1" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "selector": { "kind": "application", "id": "mystery:1" },
                "rate_bytes_per_s": 1_000_000
            }),
            serde_json::json!({
                "action": "limit",
                "direction": "outbound",
                "match": { "kind": "endpoint", "address": "203.0.113.9" },
                "rate_bytes_per_s": 1_000_000
            }),
        ];

        for body in invalid {
            let response = call(
                &state,
                json_request(Method::POST, "/v1/traffic-rules", body),
            )
            .await;
            assert_problem(&response, StatusCode::UNPROCESSABLE_ENTITY);
        }

        let response = call(&state, get("/v1/traffic-rules/99")).await;
        assert_problem(&response, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn traffic_rule_preflight_reports_targets() {
        let state = state();
        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/traffic-rules/resolve",
                serde_json::json!({
                    "direction": "outbound",
                    "selector": { "kind": "endpoint", "address": "203.0.113.9", "port": 443 }
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["plan"], "direct");
        assert_eq!(body["coverage"], "complete");
        assert_eq!(body["targets"][0]["kind"], "endpoint");
        assert_eq!(body["targets"][0]["address"], "203.0.113.9");
        assert_eq!(body["targets"][0]["port"], 443);
        assert!(body["targets"][0]["cgroup_id"].is_null());

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/traffic-rules/resolve",
                serde_json::json!({
                    "direction": "outbound",
                    "selector": { "kind": "application", "id": "cont:missing" }
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["plan"], "resolved");
        assert_eq!(body["coverage"], "unresolved");
        assert!(
            body["reason"]
                .as_str()
                .expect("reason")
                .contains("no cgroup directory")
        );
        assert_eq!(body["targets"].as_array().expect("targets").len(), 0);
    }

    #[tokio::test]
    async fn traffic_rule_limit_conflicts() {
        let state = state();
        {
            let mut inner = state.lock();
            for index in 0..MAX_TRAFFIC_RULES {
                inner
                    .db
                    .insert_traffic_rule(&TrafficRuleDraft {
                        action: ActionSpec::Block,
                        direction: RuleDirection::Outbound,
                        selector: Selector::Endpoint {
                            address: IpAddr::from(Ipv4Addr::new(203, 0, 113, index as u8 + 1)),
                            port: None,
                        },
                        enabled: true,
                    })
                    .expect("seed rule");
            }
        }

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/traffic-rules",
                serde_json::json!({
                    "action": "block",
                    "direction": "outbound",
                    "selector": { "kind": "endpoint", "address": "198.51.100.1" }
                }),
            ),
        )
        .await;
        assert_problem(&response, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn traffic_rules_apply_through_the_policy_handle() {
        let state = state();
        let (handle, source) = crate::collector::test_policy_handle();
        state.set_policy_handle(handle);

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/traffic-rules",
                serde_json::json!({
                    "action": "block",
                    "direction": "outbound",
                    "selector": { "kind": "endpoint", "address": "203.0.113.9", "port": 443 }
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = body_json(response).await;
        assert_eq!(body["state"], "active");
        assert!(!source.policy_ops().is_empty());

        let status = body_json(call(&state, get("/v1/status")).await).await;
        assert_eq!(status["enforcement"]["available"], true);
        assert_eq!(status["enforcement"]["rules_active"], 1);
        assert_eq!(status["enforcement"]["revision"], 1);
        assert!(status["enforcement"]["last_error"].is_null());
    }

    #[tokio::test]
    async fn master_switch_bypasses_rules() {
        let state = state();
        let (handle, _source) = crate::collector::test_policy_handle();
        state.set_policy_handle(handle);

        let response = call(
            &state,
            json_request(
                Method::POST,
                "/v1/traffic-rules",
                serde_json::json!({
                    "action": "limit",
                    "direction": "inbound",
                    "selector": { "kind": "cidr", "address": "192.0.2.0", "prefix_len": 24 },
                    "rate_bytes_per_s": 1_000_000
                }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);

        let response = call(
            &state,
            json_request(
                Method::PATCH,
                "/v1/settings",
                serde_json::json!({ "traffic_rules": { "enabled": false } }),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["traffic_rules"]["enabled"], false);

        let body = body_json(call(&state, get("/v1/traffic-rules")).await).await;
        assert_eq!(body[0]["state"], "bypassed");

        let status = body_json(call(&state, get("/v1/status")).await).await;
        assert_eq!(status["enforcement"]["enabled"], false);
        assert_eq!(status["enforcement"]["rules_active"], 1);
    }
}
