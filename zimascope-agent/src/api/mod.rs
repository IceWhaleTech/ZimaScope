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

mod db;

use std::{
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
    routing::{delete, get},
};
use tokio::sync::broadcast;
use tokio_stream::{Stream, StreamExt, wrappers::BroadcastStream};

use zimascope_common::model::CollectionBatch;

use self::{
    db::{Db, StreamEvent},
    dto::{
        API_VERSION, AuditEntryDto, ClearHistoryQuery, CollectorHealthDto, CreateExportRequest,
        DomainDetailDto, DomainSummaryDto, EndpointDetailDto, EndpointSummaryDto,
        EnrichmentStatusDto, ExportTaskDto, FlowDto, FlowQuery, OverviewDto, Page,
        ServiceStatusDto, SettingsSummaryDto, StreamQuery, TimeRange, collector_state_name,
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

        Self {
            inner: Arc::new(Mutex::new(Inner {
                db,
                settings,
                settings_version,
                collector_error: None,
                started_at: SystemTime::now(),
                version: config.version,
            })),
            events,
        }
    }

    /// Feeds one collection interval into storage and notifies SSE
    /// subscribers.
    pub fn ingest_batch(&self, batch: CollectionBatch) {
        let event = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            inner.db.ingest(batch, &inner.settings)
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

/// Builds the complete `/v1` router.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/overview", get(overview))
        .route("/v1/stream", get(stream))
        .route("/v1/flows", get(list_flows))
        .route("/v1/flows/{id}", get(get_flow))
        .route("/v1/endpoints", get(list_endpoints))
        .route("/v1/endpoints/{ip}", get(get_endpoint))
        .route("/v1/domains", get(list_domains))
        .route("/v1/domains/{domain}", get(get_domain))
        .route(
            "/v1/settings",
            get(get_settings).put(put_settings).patch(patch_settings),
        )
        .route("/v1/exports", get(list_exports).post(create_export))
        .route("/v1/exports/{id}", get(get_export).delete(delete_export))
        .route("/v1/exports/{id}/content", get(get_export_content))
        .route("/v1/history", delete(clear_history))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
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
}

async fn overview(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<OverviewQuery>,
) -> Result<Json<OverviewDto>, ApiError> {
    let range = query.range.unwrap_or_default();
    state.lock().db.overview(range, SystemTime::now()).map(Json)
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
    let tick = event.tick(filter);
    match serde_json::to_string(&tick) {
        Ok(data) => Event::default()
            .id(event.sequence.to_string())
            .event("tick")
            .data(data),
        Err(_) => resync_event("event serialization failed"),
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

async fn get_settings(State(state): State<ApiState>) -> Json<Settings> {
    Json(state.lock().settings.clone())
}

async fn put_settings(
    State(state): State<ApiState>,
    ApiJson(body): ApiJson<Settings>,
) -> Result<Json<Settings>, ApiError> {
    let mut inner = state.lock();
    let mut settings = body;
    settings.normalize();
    settings.validate()?;
    apply_settings(&mut inner, settings)?;
    Ok(Json(inner.settings.clone()))
}

async fn patch_settings(
    State(state): State<ApiState>,
    ApiJson(patch): ApiJson<SettingsPatch>,
) -> Result<Json<Settings>, ApiError> {
    let mut inner = state.lock();
    let mut settings = inner.settings.clone();
    patch.apply(&mut settings);
    settings.normalize();
    settings.validate()?;
    apply_settings(&mut inner, settings)?;
    Ok(Json(inner.settings.clone()))
}

fn apply_settings(inner: &mut Inner, settings: Settings) -> Result<(), ApiError> {
    inner.settings_version += 1;
    inner.db.save_settings(&settings, inner.settings_version)?;
    inner.settings = settings;
    Ok(())
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
        time::{Duration, Instant},
    };

    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use zimascope_common::model::{
        AssociationConfidence, CollectorHealth, CollectorState, DomainEvidence, DomainObservation,
        Endpoint, FlowDirection, FlowKey, FlowState, FlowUpdate, InterfaceHealth, Protocol,
        TrafficCounters,
    };

    use super::*;

    fn state() -> ApiState {
        ApiState::new(ApiConfig {
            version: "0.0.0-test".to_owned(),
            flow_capacity: 128,
            export_ttl: Duration::from_secs(3600),
            geoip_database: None,
            database: None,
        })
    }

    fn state_with_export_ttl(ttl: Duration) -> ApiState {
        ApiState::new(ApiConfig {
            version: "0.0.0-test".to_owned(),
            flow_capacity: 128,
            export_ttl: ttl,
            geoip_database: None,
            database: None,
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
        assert_eq!(body["top_endpoints"][0]["address"], "93.184.216.34");
        assert_eq!(body["top_domains"][0]["domain"], "example.com");
        assert!(body["timeline"]["points"].as_array().expect("points").len() >= 15);
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

        let response = call(&state, get("/v1/endpoints?sort=-mystery")).await;
        assert_problem(&response, StatusCode::BAD_REQUEST);
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
        assert!(frame.contains("\"health\":"), "frame: {frame}");
        assert!(frame.contains("\"remote_profile\":"), "frame: {frame}");
        assert!(frame.contains("\"scope\":\"public\""), "frame: {frame}");
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

        let body = body_json(call(&state, get("/v1/domains?sort=domain")).await).await;
        assert_eq!(body["items"][0]["domain"], "cdn.example.net");
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
}
