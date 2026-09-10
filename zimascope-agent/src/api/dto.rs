//! Wire types for the local ZimaScope API (v1).
//!
//! The API is JSON-only and speaks in the product glossary: Flows, Endpoints,
//! Associated Domains, IP Profiles, Observation Gaps and AgentHealth.
//! Timestamps are Unix epoch milliseconds so clients never need a timezone
//! database to render them.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use zimascope_common::model::{
    AddressScope, AssociationConfidence, CollectorHealth, CollectorState, DomainEvidence,
    EndReason, FlowDirection, FlowState, GapReason, Protocol,
};

/// API version prefix used by every route.
pub const API_VERSION: &str = "v1";

/// Default and maximum page sizes for cursor pagination.
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

/// Cursor-paginated collection envelope.
#[derive(Clone, Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    /// Number of resources matching the filters before pagination.
    pub total: usize,
    /// Opaque cursor for the next page; `null` on the last page.
    pub next_cursor: Option<String>,
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
pub enum DirectionParam {
    Inbound,
    Outbound,
}

impl DirectionParam {
    pub const fn matches(self, direction: FlowDirection) -> bool {
        match self {
            Self::Inbound => matches!(direction, FlowDirection::Inbound),
            Self::Outbound => matches!(direction, FlowDirection::Outbound),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolParam {
    Tcp,
    Udp,
}

impl ProtocolParam {
    pub const fn matches(self, protocol: Protocol) -> bool {
        match self {
            Self::Tcp => matches!(protocol, Protocol::Tcp),
            Self::Udp => matches!(protocol, Protocol::Udp),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowStateParam {
    Active,
    Ended,
}

impl FlowStateParam {
    pub const fn matches(self, state: FlowState) -> bool {
        match self {
            Self::Active => matches!(state, FlowState::Active),
            Self::Ended => matches!(state, FlowState::Ended(_)),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeParam {
    Public,
    Private,
    Shared,
    Loopback,
    LinkLocal,
    UniqueLocal,
    Multicast,
    Broadcast,
    Documentation,
    Reserved,
    Unspecified,
}

impl ScopeParam {
    pub const fn matches(self, scope: AddressScope) -> bool {
        matches!(
            (self, scope),
            (Self::Public, AddressScope::Public)
                | (Self::Private, AddressScope::Private)
                | (Self::Shared, AddressScope::Shared)
                | (Self::Loopback, AddressScope::Loopback)
                | (Self::LinkLocal, AddressScope::LinkLocal)
                | (Self::UniqueLocal, AddressScope::UniqueLocal)
                | (Self::Multicast, AddressScope::Multicast)
                | (Self::Broadcast, AddressScope::Broadcast)
                | (Self::Documentation, AddressScope::Documentation)
                | (Self::Reserved, AddressScope::Reserved)
                | (Self::Unspecified, AddressScope::Unspecified)
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceParam {
    Dns,
    TlsSni,
    HttpHost,
}

impl EvidenceParam {
    pub const fn matches(self, evidence: DomainEvidence) -> bool {
        matches!(
            (self, evidence),
            (Self::Dns, DomainEvidence::Dns)
                | (Self::TlsSni, DomainEvidence::TlsSni)
                | (Self::HttpHost, DomainEvidence::HttpHost)
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfidenceParam {
    Direct,
    Inferred,
}

impl ConfidenceParam {
    pub const fn matches(self, confidence: AssociationConfidence) -> bool {
        matches!(
            (self, confidence),
            (Self::Direct, AssociationConfidence::Direct)
                | (Self::Inferred, AssociationConfidence::Inferred)
        )
    }
}

/// Shared Flow filters accepted by `/v1/flows`, `/v1/endpoints`,
/// `/v1/domains` and export requests.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct FlowFilter {
    pub range: Option<TimeRange>,
    pub direction: Option<DirectionParam>,
    pub protocol: Option<ProtocolParam>,
    pub ip: Option<std::net::IpAddr>,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub scope: Option<ScopeParam>,
    pub state: Option<FlowStateParam>,
    pub has_domain: Option<bool>,
}

// Query DTOs intentionally repeat the filter fields instead of flattening
// `FlowFilter`: `serde_urlencoded` loses type information when a struct is
// buffered for flattening, which breaks numeric parameters such as `port`.
macro_rules! flow_filter_method {
    () => {
        pub fn filter(&self) -> FlowFilter {
            FlowFilter {
                range: self.range,
                direction: self.direction,
                protocol: self.protocol,
                ip: self.ip,
                src_ip: self.src_ip,
                dst_ip: self.dst_ip,
                port: self.port,
                domain: self.domain.clone(),
                country: self.country.clone(),
                asn: self.asn,
                organization: self.organization.clone(),
                scope: self.scope,
                state: self.state,
                has_domain: self.has_domain,
            }
        }
    };
}

#[derive(Clone, Debug, Deserialize)]
pub struct FlowListQuery {
    pub range: Option<TimeRange>,
    pub direction: Option<DirectionParam>,
    pub protocol: Option<ProtocolParam>,
    pub ip: Option<std::net::IpAddr>,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub scope: Option<ScopeParam>,
    pub state: Option<FlowStateParam>,
    pub has_domain: Option<bool>,
    pub sort: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl FlowListQuery {
    flow_filter_method!();
}

#[derive(Clone, Debug, Deserialize)]
pub struct EndpointListQuery {
    pub range: Option<TimeRange>,
    pub direction: Option<DirectionParam>,
    pub protocol: Option<ProtocolParam>,
    pub ip: Option<std::net::IpAddr>,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub scope: Option<ScopeParam>,
    pub state: Option<FlowStateParam>,
    pub has_domain: Option<bool>,
    pub sort: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl EndpointListQuery {
    flow_filter_method!();
}

#[derive(Clone, Debug, Deserialize)]
pub struct DomainListQuery {
    pub range: Option<TimeRange>,
    pub direction: Option<DirectionParam>,
    pub protocol: Option<ProtocolParam>,
    pub ip: Option<std::net::IpAddr>,
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub port: Option<u16>,
    pub domain: Option<String>,
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub scope: Option<ScopeParam>,
    pub state: Option<FlowStateParam>,
    pub has_domain: Option<bool>,
    pub q: Option<String>,
    pub evidence: Option<EvidenceParam>,
    pub confidence: Option<ConfidenceParam>,
    pub sort: Option<String>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

impl DomainListQuery {
    flow_filter_method!();
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

#[derive(Clone, Debug, Serialize)]
pub struct DomainRefDto {
    pub domain: String,
    pub evidence: &'static str,
    pub confidence: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct FlowDto {
    pub id: String,
    pub direction: &'static str,
    pub protocol: &'static str,
    pub state: &'static str,
    pub end_reason: Option<&'static str>,
    pub source: EndpointDto,
    pub destination: EndpointDto,
    /// Direction-relative peer: the source for inbound Flows, the
    /// destination for outbound Flows.
    pub remote: EndpointDto,
    pub interface: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub duration_ms: u64,
    pub domains: Vec<DomainRefDto>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IpProfileDto {
    pub address: String,
    pub scope: &'static str,
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
    pub scope: &'static str,
    pub country: Option<String>,
    pub region: Option<String>,
    pub asn: Option<u32>,
    pub organization: Option<String>,
    pub packets: u64,
    pub bytes: u64,
    pub flow_count: u64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PortUsageDto {
    pub port: u16,
    pub protocol: &'static str,
    pub direction: &'static str,
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
    pub evidence: &'static str,
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
    pub evidence: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DomainAddressDto {
    pub address: String,
    pub evidence: Vec<&'static str>,
    pub confidence: &'static str,
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
    pub state: &'static str,
    pub interfaces: Vec<InterfaceHealthDto>,
    pub map: MapUsageDto,
    pub kernel: KernelCountersDto,
    pub gaps: Vec<ObservationGapDto>,
}

impl CollectorHealthDto {
    pub fn from_health(health: &CollectorHealth) -> Self {
        Self {
            state: collector_state_name(health.state),
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
    pub collector: Option<CollectorHealthDto>,
    pub enrichment: EnrichmentStatusDto,
    pub settings: SettingsSummaryDto,
    pub recent_operations: Vec<AuditEntryDto>,
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
    pub filter: FlowFilter,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExportTaskDto {
    pub id: String,
    pub status: &'static str,
    pub format: ExportFormat,
    pub range: Option<&'static str>,
    pub created_at: i64,
    pub expires_at: i64,
    pub record_count: u64,
    pub size_bytes: u64,
    pub truncated: bool,
    pub content_type: &'static str,
    pub download_url: String,
}

pub const fn direction_name(direction: FlowDirection) -> &'static str {
    match direction {
        FlowDirection::Inbound => "inbound",
        FlowDirection::Outbound => "outbound",
    }
}

pub const fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

pub const fn state_name(state: FlowState) -> &'static str {
    match state {
        FlowState::Active => "active",
        FlowState::Ended(_) => "ended",
    }
}

pub const fn end_reason_name(reason: EndReason) -> &'static str {
    match reason {
        EndReason::IdleTimeout => "idle_timeout",
        EndReason::TcpFin => "tcp_fin",
        EndReason::TcpReset => "tcp_reset",
        EndReason::EvictedOrUnknown => "evicted_or_unknown",
    }
}

pub const fn evidence_name(evidence: DomainEvidence) -> &'static str {
    match evidence {
        DomainEvidence::Dns => "dns",
        DomainEvidence::TlsSni => "tls_sni",
        DomainEvidence::HttpHost => "http_host",
    }
}

pub const fn confidence_name(confidence: AssociationConfidence) -> &'static str {
    match confidence {
        AssociationConfidence::Direct => "direct",
        AssociationConfidence::Inferred => "inferred",
    }
}

pub const fn scope_name(scope: AddressScope) -> &'static str {
    match scope {
        AddressScope::Public => "public",
        AddressScope::Private => "private",
        AddressScope::Shared => "shared",
        AddressScope::Loopback => "loopback",
        AddressScope::LinkLocal => "link_local",
        AddressScope::UniqueLocal => "unique_local",
        AddressScope::Multicast => "multicast",
        AddressScope::Broadcast => "broadcast",
        AddressScope::Documentation => "documentation",
        AddressScope::Reserved => "reserved",
        AddressScope::Unspecified => "unspecified",
    }
}

pub const fn collector_state_name(state: CollectorState) -> &'static str {
    match state {
        CollectorState::Running => "running",
        CollectorState::Degraded => "degraded",
        CollectorState::Stopped => "stopped",
    }
}
