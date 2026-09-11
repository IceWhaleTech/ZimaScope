//! Wire types for the local ZimaScope API (v1).
//!
//! The API is JSON-only and speaks in the product glossary: Flows, Endpoints,
//! Associated Domains, IP Profiles, Observation Gaps and AgentHealth.
//! Timestamps are Unix epoch milliseconds. Domain enums derive `serde` so the
//! wire contract reuses the shared model instead of duplicating mappings.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use zimascope_common::model::{
    AddressScope, AssociationConfidence, CollectorHealth, CollectorState, DomainEvidence,
    EndReason, FlowDirection, FlowState, GapReason, Protocol,
};

/// API version prefix used by every route.
pub const API_VERSION: &str = "v1";

/// Default and maximum page sizes for offset pagination.
pub const DEFAULT_PAGE_LIMIT: usize = 50;
pub const MAX_PAGE_LIMIT: usize = 500;

/// RFC 9457 problem body.
#[derive(Clone, Debug, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: &'static str,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// Unix epoch milliseconds for a wall clock instant.
pub fn unix_millis(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis().min(i64::MAX as u128) as i64,
        Err(error) => -(error.duration().as_millis().min(i64::MAX as u128) as i64),
    }
}

/// Renders a unit enum as its serde string, e.g. `TlsSni` -> `"tls_sni"`.
pub fn enum_value<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .expect("unit enum serializes as a string")
}

/// Parses a stored enum string back into its shared model type.
pub fn enum_from_value<T: DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).ok()
}

/// Offset-paginated collection envelope.
#[derive(Clone, Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Number of resources matching the filters before pagination.
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

/// Time window accepted by list and overview endpoints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
pub enum TimeRange {
    #[default]
    #[serde(rename = "15m")]
    Minute15,
    #[serde(rename = "1h")]
    Hour1,
    #[serde(rename = "24h")]
    Hour24,
    #[serde(rename = "7d")]
    Day7,
}

impl TimeRange {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Minute15 => "15m",
            Self::Hour1 => "1h",
            Self::Hour24 => "24h",
            Self::Day7 => "7d",
        }
    }

    pub const fn duration(self) -> Duration {
        match self {
            Self::Minute15 => Duration::from_secs(15 * 60),
            Self::Hour1 => Duration::from_secs(60 * 60),
            Self::Hour24 => Duration::from_secs(24 * 60 * 60),
            Self::Day7 => Duration::from_secs(7 * 24 * 60 * 60),
        }
    }

    pub fn cutoff(self, now: SystemTime) -> SystemTime {
        now.checked_sub(self.duration())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowStateParam {
    Active,
    Ended,
}

impl FlowStateParam {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ended => "ended",
        }
    }
}

/// Shared query accepted by `/v1/flows`, `/v1/endpoints`, `/v1/domains` and
/// export requests.
///
/// The struct is intentionally flat: `serde_urlencoded` cannot flatten
/// numeric fields, and one shared shape removes the previous per-resource
/// copies.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct FlowQuery {
    /// Case-insensitive substring search over Flow id, direction, protocol,
    /// state, end reason, source/destination IP and port, interface name and
    /// associated domains.
    pub q: Option<String>,
    pub range: Option<TimeRange>,
    pub direction: Option<FlowDirection>,
    pub protocol: Option<Protocol>,
    pub ip: Option<std::net::IpAddr>,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub scope: Option<AddressScope>,
    pub state: Option<FlowStateParam>,
    pub has_domain: Option<bool>,
    pub evidence: Option<DomainEvidence>,
    pub confidence: Option<AssociationConfidence>,
    /// `field` or `-field`; defaults per resource.
    pub sort: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClearHistoryQuery {
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointDto {
    pub address: String,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRefDto {
    pub domain: String,
    pub evidence: DomainEvidence,
    pub confidence: AssociationConfidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlowDto {
    pub id: String,
    pub direction: FlowDirection,
    pub protocol: Protocol,
    pub state: &'static str,
    pub end_reason: Option<EndReason>,
    pub source: EndpointDto,
    pub destination: EndpointDto,
    /// Direction-relative peer: the source for inbound Flows, the
    /// destination for outbound Flows.
    pub remote: EndpointDto,
    /// Locally enriched profile of `remote.address` (PRD 8.5). Always
    /// present; without a GeoIP/ASN database it carries `scope` only.
    pub remote_profile: IpProfileDto,
    pub interface: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub duration_ms: u64,
    pub domains: Vec<DomainRefDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpProfileDto {
    pub address: String,
    pub scope: AddressScope,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city_approximate: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub database_version: Option<String>,
    pub enriched_at: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointSummaryDto {
    pub address: String,
    pub scope: AddressScope,
    pub country: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub flow_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortUsageDto {
    pub port: u16,
    pub protocol: Protocol,
    pub direction: FlowDirection,
    pub packets: u64,
    pub bytes: u64,
    pub flow_count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointDetailDto {
    pub address: String,
    pub profile: IpProfileDto,
    pub packets: u64,
    pub bytes: u64,
    pub flow_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub ports: Vec<PortUsageDto>,
    pub domains: Vec<DomainRefDto>,
    pub flows_url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceCountDto {
    pub evidence: DomainEvidence,
    pub flows: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DomainSummaryDto {
    pub domain: String,
    pub packets: u64,
    pub bytes: u64,
    pub flow_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub evidence: Vec<DomainEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DomainAddressDto {
    pub address: String,
    pub evidence: Vec<DomainEvidence>,
    pub confidence: AssociationConfidence,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub bytes: u64,
    pub last_seen: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CountryCountDto {
    pub country: String,
    pub bytes: u64,
    pub flows: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct AsnCountDto {
    pub asn: u32,
    pub organization: Option<String>,
    pub bytes: u64,
    pub flows: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DomainDetailDto {
    pub domain: String,
    pub packets: u64,
    pub bytes: u64,
    pub flow_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub evidence: Vec<EvidenceCountDto>,
    pub addresses: Vec<DomainAddressDto>,
    pub countries: Vec<CountryCountDto>,
    pub asns: Vec<AsnCountDto>,
    pub flows_url: String,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct CountersDto {
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct RateDto {
    pub inbound_bps: u64,
    pub outbound_bps: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct DirectionTotalsDto {
    pub inbound: CountersDto,
    pub outbound: CountersDto,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TimelinePointDto {
    pub start: i64,
    pub inbound: CountersDto,
    pub outbound: CountersDto,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TimelineDto {
    pub resolution: &'static str,
    pub points: Vec<TimelinePointDto>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct DomainVisibilityDto {
    pub flows_with_domain: u64,
    pub flows_total: u64,
    pub ratio: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct OverviewDto {
    pub range: &'static str,
    pub generated_at: i64,
    pub rates: RateDto,
    pub totals: DirectionTotalsDto,
    pub timeline: TimelineDto,
    pub top_endpoints: Vec<EndpointSummaryDto>,
    pub top_domains: Vec<DomainSummaryDto>,
    pub top_countries: Vec<CountryCountDto>,
    pub top_asns: Vec<AsnCountDto>,
    pub active_flows: u64,
    pub domain_visibility: DomainVisibilityDto,
    pub health: Option<CollectorHealthDto>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InterfaceHealthDto {
    pub ifindex: u32,
    pub name: String,
    pub ingress_attached: bool,
    pub egress_attached: bool,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct MapUsageDto {
    pub entries: usize,
    pub capacity: usize,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct KernelCountersDto {
    pub packets_seen: u64,
    pub packets_parsed: u64,
    pub parse_failures: u64,
    pub map_update_failures: u64,
    pub flow_evictions: u64,
    pub domain_events_emitted: u64,
    pub domain_events_dropped: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObservationGapDto {
    pub kind: &'static str,
    pub ifindex: Option<u32>,
    pub started_at: i64,
    pub ended_at: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CollectorHealthDto {
    pub state: CollectorState,
    pub interfaces: Vec<InterfaceHealthDto>,
    pub map: MapUsageDto,
    pub kernel: KernelCountersDto,
    pub gaps: Vec<ObservationGapDto>,
}

impl CollectorHealthDto {
    pub fn from_health(health: &CollectorHealth) -> Self {
        Self {
            state: health.state,
            interfaces: health
                .attached_interfaces
                .iter()
                .map(|interface| InterfaceHealthDto {
                    ifindex: interface.ifindex.get(),
                    name: interface.name.to_string(),
                    ingress_attached: interface.ingress_attached,
                    egress_attached: interface.egress_attached,
                    last_error: interface.last_error.as_ref().map(ToString::to_string),
                })
                .collect(),
            map: MapUsageDto {
                entries: health.map_entries,
                capacity: health.map_capacity,
            },
            kernel: KernelCountersDto {
                packets_seen: health.kernel.packets_seen,
                packets_parsed: health.kernel.packets_parsed,
                parse_failures: health.kernel.parse_failures,
                map_update_failures: health.kernel.map_update_failures,
                flow_evictions: health.kernel.flow_evictions,
                domain_events_emitted: health.kernel.domain_events_emitted,
                domain_events_dropped: health.kernel.domain_events_dropped,
            },
            gaps: health
                .gaps
                .iter()
                .map(|gap| {
                    let (kind, ifindex) = match gap.reason {
                        GapReason::InterfaceDetached { ifindex } => {
                            ("interface_detached", Some(ifindex))
                        }
                        GapReason::MapReadFailed => ("map_read_failed", None),
                    };
                    ObservationGapDto {
                        kind,
                        ifindex,
                        started_at: unix_millis(gap.started_at),
                        ended_at: gap.ended_at.map(unix_millis),
                    }
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrichmentStatusDto {
    pub database_version: Option<String>,
    pub loaded_at: Option<i64>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct AuditEntryDto {
    pub at: i64,
    pub action: &'static str,
    pub outcome: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct SettingsSummaryDto {
    pub enabled: bool,
    pub boundary_interfaces: Vec<String>,
    pub domain_observation: bool,
    pub history_enabled: bool,
    pub retention_days: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatusDto {
    pub service: &'static str,
    pub version: String,
    pub api_version: &'static str,
    pub started_at: i64,
    pub uptime_seconds: u64,
    pub last_batch_at: Option<i64>,
    pub batch_sequence: u64,
    pub collector_error: Option<String>,
    pub database_error: Option<String>,
    pub collector: Option<CollectorHealthDto>,
    pub enrichment: EnrichmentStatusDto,
    pub settings: SettingsSummaryDto,
    pub recent_operations: Vec<AuditEntryDto>,
}

pub const fn collector_state_name(state: CollectorState) -> &'static str {
    match state {
        CollectorState::Running => "running",
        CollectorState::Degraded => "degraded",
        CollectorState::Stopped => "stopped",
    }
}

pub const fn flow_state_name(state: FlowState) -> &'static str {
    match state {
        FlowState::Active => "active",
        FlowState::Ended(_) => "ended",
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Json,
    Csv,
}

impl ExportFormat {
    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Csv => "text/csv",
        }
    }

    pub const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateExportRequest {
    #[serde(default)]
    pub format: ExportFormat,
    #[serde(flatten)]
    pub query: FlowQuery,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportTaskDto {
    pub id: String,
    pub status: &'static str,
    pub format: ExportFormat,
    pub range: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub record_count: u64,
    pub size_bytes: u64,
    pub truncated: bool,
    pub content_type: String,
    pub download_url: String,
}

/// Server-Sent Event payload for `GET /v1/stream` (`event: tick`).
///
/// One `tick` describes a single collection interval. `flows` are complete
/// upserts keyed by `id`: replace any locally known Flow with the same id.
/// `domains` are new or refreshed associations observed in the interval.
#[derive(Clone, Debug, Serialize)]
pub struct TickDto {
    pub sequence: u64,
    pub collected_at: i64,
    pub interval_ms: u64,
    pub traffic: TickTrafficDto,
    pub flows: Vec<FlowDto>,
    pub domains: Vec<DomainObservationDto>,
    pub health: Option<CollectorHealthDto>,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TickTrafficDto {
    pub inbound_bps: u64,
    pub outbound_bps: u64,
    pub inbound: CountersDto,
    pub outbound: CountersDto,
}

#[derive(Clone, Debug, Serialize)]
pub struct DomainObservationDto {
    pub domain: String,
    pub address: String,
    pub evidence: DomainEvidence,
    pub confidence: AssociationConfidence,
    pub observed_at: i64,
}

/// Filters accepted by `GET /v1/stream`.
///
/// Only filters that can be evaluated on a live Flow update are accepted;
/// historical (`range`) and enrichment-backed filters (`country`, `asn`,
/// `organization`, `scope`) are rejected so the stream never pretends to
/// apply a filter it cannot evaluate. `q` uses the same searchable fields as
/// the REST lists.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamQuery {
    pub q: Option<String>,
    pub direction: Option<FlowDirection>,
    pub protocol: Option<Protocol>,
    pub ip: Option<std::net::IpAddr>,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub state: Option<FlowStateParam>,
    pub has_domain: Option<bool>,
}

impl StreamQuery {
    pub fn filter(&self) -> StreamFilter {
        StreamFilter {
            q: self
                .q
                .as_deref()
                .map(|q| q.trim().to_ascii_lowercase())
                .filter(|q| !q.is_empty()),
            direction: self.direction,
            protocol: self.protocol,
            ip: self.ip.map(|ip| ip.to_string()),
            src_ip: self.src_ip.map(|ip| ip.to_string()),
            dst_ip: self.dst_ip.map(|ip| ip.to_string()),
            port: self.port,
            domain: self
                .domain
                .as_deref()
                .map(|domain| domain.trim().trim_end_matches('.').to_ascii_lowercase()),
            state: self.state,
            has_domain: self.has_domain,
        }
    }
}

/// Precomputed filter for live Flow updates.
#[derive(Clone, Debug, Default)]
pub struct StreamFilter {
    q: Option<String>,
    direction: Option<FlowDirection>,
    protocol: Option<Protocol>,
    ip: Option<String>,
    src_ip: Option<String>,
    dst_ip: Option<String>,
    port: Option<u16>,
    domain: Option<String>,
    state: Option<FlowStateParam>,
    has_domain: Option<bool>,
}

impl StreamFilter {
    pub fn matches(&self, flow: &FlowDto) -> bool {
        if let Some(q) = &self.q {
            if !flow_search_text(flow).contains(q.as_str()) {
                return false;
            }
        }
        if let Some(direction) = self.direction {
            if flow.direction != direction {
                return false;
            }
        }
        if let Some(protocol) = self.protocol {
            if flow.protocol != protocol {
                return false;
            }
        }
        if let Some(ip) = &self.ip {
            if &flow.source.address != ip && &flow.destination.address != ip {
                return false;
            }
        }
        if let Some(src_ip) = &self.src_ip {
            if &flow.source.address != src_ip {
                return false;
            }
        }
        if let Some(dst_ip) = &self.dst_ip {
            if &flow.destination.address != dst_ip {
                return false;
            }
        }
        if let Some(port) = self.port {
            if flow.source.port != Some(port) && flow.destination.port != Some(port) {
                return false;
            }
        }
        if let Some(domain) = &self.domain {
            if !flow
                .domains
                .iter()
                .any(|candidate| &candidate.domain == domain)
            {
                return false;
            }
        }
        if let Some(state) = self.state {
            if flow.state != state.as_str() {
                return false;
            }
        }
        if let Some(has_domain) = self.has_domain {
            if flow.domains.is_empty() == has_domain {
                return false;
            }
        }
        true
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        self.domain
            .as_deref()
            .is_none_or(|candidate| candidate == domain)
    }
}

/// Lowercase searchable text of a Flow update, matching the fields used by
/// the REST `q` filter.
fn flow_search_text(flow: &FlowDto) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(160);
    let _ = write!(
        text,
        "{} {} {} {} ",
        flow.id,
        enum_value(flow.direction),
        enum_value(flow.protocol),
        flow.state
    );
    if let Some(reason) = flow.end_reason {
        let _ = write!(text, "{} ", enum_value(reason));
    }
    let _ = write!(text, "{} ", flow.source.address);
    if let Some(port) = flow.source.port {
        let _ = write!(text, "{port} ");
    }
    let _ = write!(text, "{} ", flow.destination.address);
    if let Some(port) = flow.destination.port {
        let _ = write!(text, "{port} ");
    }
    if let Some(interface) = &flow.interface {
        let _ = write!(text, "{interface} ");
    }
    for domain in &flow.domains {
        let _ = write!(text, "{} ", domain.domain);
    }
    text.make_ascii_lowercase();
    text
}
