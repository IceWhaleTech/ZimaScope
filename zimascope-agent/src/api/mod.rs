//! Local REST API for the ZimaScope agent.
//!
//! The API is versioned under `/v1`, JSON-only, and served on a Unix socket.
//! Collection is never blocked by API work: batches are ingested into bounded
//! state and every read endpoint answers from that state.
//!
//! Conventions:
//!
//! - Resources are plural nouns; item resources use the natural key
//!   (`/v1/flows/{id}`, `/v1/endpoints/{ip}`, `/v1/domains/{domain}`).
//! - Lists are cursor-paginated with `limit` and an opaque `cursor`.
//! - Failures use RFC 9457 `application/problem+json`.
//! - Mutations are idempotent: `PUT /v1/settings` replaces settings,
//!   `DELETE /v1/history` and `DELETE /v1/exports/{id}` are safe to repeat.
//! - Destructive operations require an explicit precondition
//!   (`DELETE /v1/history?confirm=true` returns `428` otherwise).

pub mod dto;
mod error;
mod settings;
mod store;

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::SystemTime,
};

use axum::{
    Json, Router,
    extract::{
        FromRequest, FromRequestParts, OriginalUri, Path as AxumPath, Query, Request, State,
    },
    http::{HeaderMap, HeaderValue, Method, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
    routing::{delete, get},
};

use zimascope_common::model::CollectionBatch;

use self::{
    dto::{
        API_VERSION, AuditEntryDto, ClearHistoryQuery, CollectorHealthDto, CreateExportRequest,
        DomainDetailDto, DomainListQuery, DomainSummaryDto, EndpointDetailDto, EndpointListQuery,
        EndpointSummaryDto, EnrichmentStatusDto, ExportTaskDto, FlowDto, FlowListQuery,
        OverviewDto, Page, ServiceStatusDto, SettingsSummaryDto, TimeRange, unix_millis,
    },
    error::ApiError,
    settings::{Settings, SettingsPatch},
    store::Store,
};

pub use self::{dto::ExportFormat, error::PROBLEM_CONTENT_TYPE, store::ApiConfig};

/// Cloneable shared state for every API handler.
#[derive(Clone)]
pub struct ApiState {
    inner: Arc<Mutex<Inner>>,
}

struct Inner {
    store: Store,
    settings: Settings,
    settings_version: u64,
    collector_error: Option<String>,
    started_at: SystemTime,
    version: String,
}

impl ApiState {
    pub fn new(config: ApiConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                store: Store::new(&config),
                settings: Settings::default(),
                settings_version: 0,
                collector_error: None,
                started_at: SystemTime::now(),
                version: config.version,
            })),
        }
    }

    /// Feeds one collection interval into the read model.
    pub fn ingest_batch(&self, batch: CollectionBatch) {
        self.lock().store.ingest(batch);
    }

    /// Records why collection is unavailable so `/v1/status` can explain it.
    pub fn set_collector_error(&self, error: impl Into<String>) {
        self.lock().collector_error = Some(error.into());
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Inner {
    fn etag(&self) -> String {
        format!("\"v{}\"", self.settings_version)
    }

    fn status(&self) -> ServiceStatusDto {
        let health = self.store.health();
        let service = if self.collector_error.is_some() {
            "unavailable"
        } else {
            match health {
                Some(health) => dto::collector_state_name(health.state),
                None => "starting",
            }
        };
        let (enrichment, enrichment_error) = self.store.enrichment_status();

        ServiceStatusDto {
            service,
            version: self.version.clone(),
            api_version: API_VERSION,
            started_at: unix_millis(self.started_at),
            uptime_seconds: SystemTime::now()
                .duration_since(self.started_at)
                .map(|duration| duration.as_secs())
                .unwrap_or(0),
            last_batch_at: self.store.last_batch_at().map(unix_millis),
            batch_sequence: self.store.batch_sequence(),
            collector_error: self.collector_error.clone(),
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
                .store
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
        .route("/v1", get(describe))
        .route("/v1/status", get(status))
        .route("/v1/overview", get(overview))
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

#[derive(serde::Serialize)]
struct ApiDescription {
    name: &'static str,
    api_version: &'static str,
    resources: Vec<ResourceLink>,
}

#[derive(serde::Serialize)]
struct ResourceLink {
    name: &'static str,
    href: &'static str,
}

async fn describe() -> Json<ApiDescription> {
    Json(ApiDescription {
        name: "ZimaScope local API",
        api_version: API_VERSION,
        resources: vec![
            ResourceLink {
                name: "status",
                href: "/v1/status",
            },
            ResourceLink {
                name: "overview",
                href: "/v1/overview",
            },
            ResourceLink {
                name: "flows",
                href: "/v1/flows",
            },
            ResourceLink {
                name: "endpoints",
                href: "/v1/endpoints",
            },
            ResourceLink {
                name: "domains",
                href: "/v1/domains",
            },
            ResourceLink {
                name: "settings",
                href: "/v1/settings",
            },
            ResourceLink {
                name: "exports",
                href: "/v1/exports",
            },
            ResourceLink {
                name: "history",
                href: "/v1/history",
            },
        ],
    })
}

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
) -> Json<OverviewDto> {
    let range = query.range.unwrap_or_default();
    Json(state.lock().store.overview(range, SystemTime::now()))
}

async fn list_flows(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<FlowListQuery>,
) -> Result<Json<Page<FlowDto>>, ApiError> {
    state.lock().store.list_flows(&query).map(Json)
}

async fn get_flow(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<FlowDto>, ApiError> {
    state.lock().store.get_flow(&id).map(Json)
}

async fn list_endpoints(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<EndpointListQuery>,
) -> Result<Json<Page<EndpointSummaryDto>>, ApiError> {
    state.lock().store.list_endpoints(&query).map(Json)
}

async fn get_endpoint(
    State(state): State<ApiState>,
    AxumPath(ip): AxumPath<String>,
) -> Result<Json<EndpointDetailDto>, ApiError> {
    state.lock().store.get_endpoint(&ip).map(Json)
}

async fn list_domains(
    State(state): State<ApiState>,
    ApiQuery(query): ApiQuery<DomainListQuery>,
) -> Result<Json<Page<DomainSummaryDto>>, ApiError> {
    state.lock().store.list_domains(&query).map(Json)
}

async fn get_domain(
    State(state): State<ApiState>,
    AxumPath(domain): AxumPath<String>,
) -> Result<Json<DomainDetailDto>, ApiError> {
    state.lock().store.get_domain(&domain).map(Json)
}

async fn get_settings(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let inner = state.lock();
    let etag = HeaderValue::from_str(&inner.etag()).expect("valid ETag");
    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|value| value.as_bytes() == etag.as_bytes())
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    ([(header::ETAG, etag)], Json(inner.settings.clone())).into_response()
}

async fn put_settings(
    State(state): State<ApiState>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Settings>,
) -> Result<Response, ApiError> {
    let mut inner = state.lock();
    check_if_match(&inner, &headers)?;

    let mut settings = body;
    settings.normalize();
    settings.validate()?;
    apply_settings(&mut inner, settings);
    Ok(settings_response(&inner))
}

async fn patch_settings(
    State(state): State<ApiState>,
    headers: HeaderMap,
    ApiJson(patch): ApiJson<SettingsPatch>,
) -> Result<Response, ApiError> {
    let mut inner = state.lock();
    check_if_match(&inner, &headers)?;

    let mut settings = inner.settings.clone();
    patch.apply(&mut settings);
    settings.normalize();
    settings.validate()?;
    apply_settings(&mut inner, settings);
    Ok(settings_response(&inner))
}

fn check_if_match(inner: &Inner, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(if_match) = headers.get(header::IF_MATCH) else {
        return Ok(());
    };
    let etag = HeaderValue::from_str(&inner.etag()).expect("valid ETag");
    if if_match.as_bytes() == etag.as_bytes() {
        Ok(())
    } else {
        Err(ApiError::precondition_failed(
            "settings were modified by another client",
        ))
    }
}

fn apply_settings(inner: &mut Inner, settings: Settings) {
    inner.store.apply_settings(&settings);
    inner.settings = settings;
    inner.settings_version += 1;
}

fn settings_response(inner: &Inner) -> Response {
    let etag = HeaderValue::from_str(&inner.etag()).expect("valid ETag");
    ([(header::ETAG, etag)], Json(inner.settings.clone())).into_response()
}

async fn list_exports(State(state): State<ApiState>) -> Json<Page<ExportTaskDto>> {
    let items = state.lock().store.list_exports();
    let total = items.len();
    Json(Page {
        items,
        total,
        next_cursor: None,
    })
}

async fn create_export(
    State(state): State<ApiState>,
    ApiJson(body): ApiJson<CreateExportRequest>,
) -> Result<Response, ApiError> {
    let mut inner = state.lock();
    let task = inner.store.create_export(&body)?;
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
    state.lock().store.get_export(&id).map(Json)
}

async fn get_export_content(
    State(state): State<ApiState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Response, ApiError> {
    let content = state.lock().store.export_content(&id)?;
    let content_type = HeaderValue::from_static(content.content_type);
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
    state.lock().store.delete_export(&id)?;
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
    state.lock().store.clear_history();
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
        })
    }

    fn state_with_export_ttl(ttl: Duration) -> ApiState {
        ApiState::new(ApiConfig {
            version: "0.0.0-test".to_owned(),
            flow_capacity: 128,
            export_ttl: ttl,
            geoip_database: None,
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
    async fn describes_itself_at_the_api_root() {
        let response = call(&state(), get("/v1")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["api_version"], "v1");
        assert!(
            body["resources"]
                .as_array()
                .expect("resources")
                .iter()
                .any(|resource| resource["href"] == "/v1/status")
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
    }

    #[tokio::test]
    async fn flows_filter_and_paginate_with_cursors() {
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

        let body = body_json(call(&state, get("/v1/flows?limit=2")).await).await;
        assert_eq!(body["total"], 3);
        let items = body["items"].as_array().expect("items");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["remote"]["address"], "1.1.1.1");
        let cursor = body["next_cursor"].as_str().expect("next cursor");

        let body =
            body_json(call(&state, get(&format!("/v1/flows?limit=2&cursor={cursor}"))).await).await;
        assert_eq!(body["items"].as_array().expect("items").len(), 1);
        assert!(body["next_cursor"].is_null());

        let body = body_json(call(&state, get("/v1/flows?direction=inbound")).await).await;
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["direction"], "inbound");
        assert_eq!(body["items"][0]["remote"]["address"], "9.9.9.9");

        let body = body_json(call(&state, get("/v1/flows?port=55000")).await).await;
        assert_eq!(body["total"], 1, "unexpected body: {body}");
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
    async fn cursor_must_match_the_sort_order() {
        let state = state();
        state.ingest_batch(batch(
            1,
            vec![outbound(("1.1.1.1", 443), 10, 1_000, Duration::ZERO)],
        ));
        let body = body_json(call(&state, get("/v1/flows?limit=1")).await).await;
        let cursor = body["next_cursor"].as_str().unwrap_or("invalid");

        let response = call(
            &state,
            get(&format!("/v1/flows?sort=bytes&cursor={cursor}")),
        )
        .await;
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

        let body = body_json(call(&state, get("/v1/endpoints/93.184.216.34")).await).await;
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
    async fn settings_validate_normalize_and_guard_with_etags() {
        let state = state();

        let response = call(&state, get("/v1/settings")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let etag = response
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("etag")
            .to_owned();
        assert_eq!(etag, "\"v0\"");

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
        assert_eq!(
            response
                .headers()
                .get(header::ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"v1\"")
        );
        let body = body_json(response).await;
        assert_eq!(body["history"]["retention_days"], 30);
        assert_eq!(body["domains"]["enabled"], false);
        assert_eq!(body["domains"]["tls_sni"], false);

        let response = call(
            &state,
            Request::builder()
                .method(Method::PUT)
                .uri("/v1/settings")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::IF_MATCH, "\"v0\"")
                .body(Body::from(serde_json::json!({}).to_string()))
                .expect("valid request"),
        )
        .await;
        assert_problem(&response, StatusCode::PRECONDITION_FAILED);
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
        let download_url = body["download_url"]
            .as_str()
            .expect("download url")
            .to_owned();

        let body = body_json(call(&state, get("/v1/exports")).await).await;
        assert_eq!(body["total"], 1);

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

        let response = call(&state, get("/v1/endpoints?scope=loopback")).await;
        let body = body_json(response).await;
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn endpoint_profile_uses_the_geoip_database() {
        let state = state();
        state
            .lock()
            .store
            .set_geoip_database(crate::enrichment::database::test_database());
        state.ingest_batch(batch(
            1,
            vec![outbound(("8.8.8.8", 53), 5, 500, Duration::ZERO)],
        ));

        let body = body_json(call(&state, get("/v1/endpoints/8.8.8.8")).await).await;
        assert_eq!(body["profile"]["country"], "US");
        assert_eq!(body["profile"]["asn"], 15169);
        assert_eq!(body["profile"]["organization"], "Google LLC");

        let body = body_json(call(&state, get("/v1/overview?range=15m")).await).await;
        assert_eq!(body["top_countries"][0]["country"], "US");
        assert_eq!(body["top_asns"][0]["asn"], 15169);
    }
}
