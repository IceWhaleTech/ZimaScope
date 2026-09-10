//! In-memory read model behind the local API.
//!
//! `Store` owns every derived view the API serves: live Flows, domain
//! associations, endpoint and domain aggregates, traffic buckets, settings
//! runtime limits and export tasks. It ingests `CollectionBatch` values in
//! sequence and answers read queries against bounded state. Replacing this
//! module with SQLite-backed storage later keeps the HTTP contract unchanged.

use std::{
    collections::VecDeque,
    fmt::Write as _,
    hash::{Hash, Hasher},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use hashbrown::{HashMap, HashSet};
use zimascope_common::model::{
    AddressScope, AssociationConfidence, CollectionBatch, CollectorHealth, DomainEvidence,
    Endpoint, FlowDirection, FlowKey, FlowState, FlowUpdate, IpProfile, Protocol, TrafficCounters,
};

#[cfg(test)]
use crate::enrichment::GeoIpDatabase;
use crate::enrichment::{DEFAULT_CACHE_CAPACITY, Enricher, EnrichmentStats};

use super::dto::{
    AsnCountDto, CollectorHealthDto, CountersDto, CountryCountDto, CreateExportRequest,
    DirectionTotalsDto, DomainAddressDto, DomainDetailDto, DomainListQuery, DomainObservationDto,
    DomainRefDto, DomainSummaryDto, DomainVisibilityDto, EndpointDetailDto, EndpointDto,
    EndpointListQuery, EndpointSummaryDto, EvidenceCountDto, ExportFormat, ExportTaskDto, FlowDto,
    FlowFilter, FlowListQuery, IpProfileDto, OverviewDto, Page, PortUsageDto, RateDto,
    StreamFilter, TickDto, TickTrafficDto, TimeRange, TimelineDto, TimelinePointDto,
    confidence_name, direction_name, end_reason_name, evidence_name, protocol_name, scope_name,
    state_name, unix_millis,
};
use super::error::ApiError;
use super::settings::Settings;

const EXPORT_MAX_RECORDS: usize = 10_000;
const MINUTE_BUCKET_CAPACITY: usize = 121;
const HOUR_BUCKET_CAPACITY: usize = 169;
const MAX_TIMELINE_POINTS: usize = 200;
const MAX_DOMAIN_CANDIDATES: usize = 8;
const TOP_LIST_LIMIT: usize = 10;
const AUDIT_CAPACITY: usize = 32;
const CSV_HEADER: &str = "id,direction,protocol,state,end_reason,src_ip,src_port,dst_ip,dst_port,remote_ip,remote_port,interface,packets,bytes,first_seen_ms,last_seen_ms,domain,evidence,confidence\n";

/// Runtime configuration for the API state.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    pub version: String,
    pub flow_capacity: usize,
    pub export_ttl: Duration,
    pub geoip_database: Option<std::path::PathBuf>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            flow_capacity: 65_536,
            export_ttl: Duration::from_secs(24 * 60 * 60),
            geoip_database: None,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ObservationKey {
    domain: Box<str>,
    address: IpAddr,
    evidence: DomainEvidence,
}

#[derive(Clone, Debug)]
struct ObservationRecord {
    domain: Box<str>,
    evidence: DomainEvidence,
    confidence: AssociationConfidence,
    last_observed: SystemTime,
    expires_at: SystemTime,
}

#[derive(Clone, Debug)]
struct DomainAssociation {
    domain: Box<str>,
    evidence: DomainEvidence,
    confidence: AssociationConfidence,
}

#[derive(Clone, Debug)]
struct FlowRecord {
    id: u64,
    key: FlowKey,
    total: TrafficCounters,
    first_seen: SystemTime,
    last_seen: SystemTime,
    state: FlowState,
    domains: Vec<DomainAssociation>,
    remote_profile: Option<Arc<IpProfile>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Rates {
    inbound_bps: u64,
    outbound_bps: u64,
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    start: SystemTime,
    inbound: TrafficCounters,
    outbound: TrafficCounters,
}

#[derive(Clone, Copy, Debug)]
struct AuditEntry {
    at: SystemTime,
    action: &'static str,
    outcome: &'static str,
}

#[derive(Clone, Debug)]
struct ExportRecord {
    id: String,
    format: ExportFormat,
    range: Option<TimeRange>,
    created_at: SystemTime,
    expires_at: SystemTime,
    record_count: u64,
    truncated: bool,
    content_type: &'static str,
    content: Vec<u8>,
}

impl ExportRecord {
    fn status(&self, now: SystemTime) -> &'static str {
        if now >= self.expires_at {
            "expired"
        } else {
            "completed"
        }
    }

    fn dto(&self, now: SystemTime) -> ExportTaskDto {
        ExportTaskDto {
            id: self.id.clone(),
            status: self.status(now),
            format: self.format,
            range: self.range.map(TimeRange::as_str),
            created_at: unix_millis(self.created_at),
            expires_at: unix_millis(self.expires_at),
            record_count: self.record_count,
            size_bytes: self.content.len() as u64,
            truncated: self.truncated,
            content_type: self.content_type,
            download_url: format!("/v1/exports/{}/content", self.id),
        }
    }
}

pub(crate) struct ExportContent {
    pub content_type: &'static str,
    pub file_name: String,
    pub bytes: Vec<u8>,
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
    pub(crate) fn tick(&self, filter: &StreamFilter) -> TickDto {
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

#[derive(Clone, Debug)]
struct EndpointAggregate {
    address: IpAddr,
    address_string: String,
    profile: Option<Arc<IpProfile>>,
    packets: u64,
    bytes: u64,
    flow_count: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    domains: Vec<DomainAssociation>,
}

#[derive(Clone, Debug)]
struct DomainAddressAggregate {
    evidence: Vec<DomainEvidence>,
    confidence: AssociationConfidence,
    profile: Option<Arc<IpProfile>>,
    packets: u64,
    bytes: u64,
    last_seen: SystemTime,
}

#[derive(Clone, Debug)]
struct DomainAggregate {
    domain: String,
    packets: u64,
    bytes: u64,
    flow_count: u64,
    first_seen: SystemTime,
    last_seen: SystemTime,
    evidence_flows: Vec<(DomainEvidence, u64)>,
    confidence: Option<AssociationConfidence>,
    addresses: HashMap<IpAddr, DomainAddressAggregate>,
}

/// Bounded, queryable state for the local API.
pub(crate) struct Store {
    flows: HashMap<u64, FlowRecord>,
    observations: HashMap<ObservationKey, ObservationRecord>,
    address_index: HashMap<IpAddr, Vec<ObservationKey>>,
    interfaces: HashMap<u32, Box<str>>,
    health: Option<CollectorHealth>,
    last_batch_at: Option<SystemTime>,
    last_interval: Duration,
    batch_sequence: u64,
    rates: Rates,
    minute_buckets: VecDeque<Bucket>,
    hour_buckets: VecDeque<Bucket>,
    exports: VecDeque<ExportRecord>,
    audit: VecDeque<AuditEntry>,
    enricher: Enricher,
    enrichment_error: Option<String>,
    flow_capacity: usize,
    export_ttl: Duration,
    export_counter: u64,
}

impl Store {
    pub(crate) fn new(config: &ApiConfig) -> Self {
        let mut enricher =
            Enricher::new(NonZeroUsize::new(DEFAULT_CACHE_CAPACITY).expect("non-zero capacity"));
        let mut enrichment_error = None;
        if let Some(path) = &config.geoip_database {
            if let Err(error) = enricher.load_database(path) {
                enrichment_error = Some(format!("{error:#}"));
            }
        }

        Self {
            flows: HashMap::new(),
            observations: HashMap::new(),
            address_index: HashMap::new(),
            interfaces: HashMap::new(),
            health: None,
            last_batch_at: None,
            last_interval: Duration::from_secs(1),
            batch_sequence: 0,
            rates: Rates::default(),
            minute_buckets: VecDeque::new(),
            hour_buckets: VecDeque::new(),
            exports: VecDeque::new(),
            audit: VecDeque::new(),
            enricher,
            enrichment_error,
            flow_capacity: config.flow_capacity.max(1),
            export_ttl: config.export_ttl,
            export_counter: 0,
        }
    }

    // ----------------------------------------------------------------- ingest

    pub(crate) fn ingest(&mut self, batch: CollectionBatch) -> StreamEvent {
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

        let mut touched: Vec<u64> = Vec::new();
        let mut domain_events: Vec<DomainObservationDto> = Vec::new();
        let mut changed_addresses = HashSet::new();
        for observation in &domains {
            if self.store_observation(observation, now_instant, now_system) {
                changed_addresses.insert(observation.address);
                domain_events.push(DomainObservationDto {
                    domain: normalize_domain(&observation.domain),
                    address: observation.address.to_string(),
                    evidence: evidence_name(observation.evidence),
                    confidence: confidence_name(observation.confidence),
                    observed_at: unix_millis(instant_to_system(
                        observation.observed_at,
                        now_instant,
                        now_system,
                    )),
                });
            }
        }

        if !changed_addresses.is_empty() {
            for (id, record) in self.flows.iter_mut() {
                let address = remote_endpoint(&record.key).address;
                if changed_addresses.contains(&address) {
                    record.domains = associate_observations(
                        &self.observations,
                        &self.address_index,
                        address,
                        now_system,
                    );
                    touched.push(*id);
                }
            }
        }

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
        self.add_buckets(collected_at, inbound, outbound);

        for update in flows {
            touched.push(flow_id(&update.key));
            self.observe_flow(update, now_instant, now_system);
        }

        let mut seen = HashSet::new();
        let updated_flows = touched
            .into_iter()
            .filter(|id| seen.insert(*id))
            .filter_map(|id| self.flows.get(&id))
            .map(|record| flow_dto(record, &self.interfaces))
            .collect();

        StreamEvent {
            sequence,
            collected_at,
            interval,
            inbound,
            outbound,
            inbound_bps: self.rates.inbound_bps,
            outbound_bps: self.rates.outbound_bps,
            flows: updated_flows,
            domains: domain_events,
            health: health_dto,
        }
    }

    fn store_observation(
        &mut self,
        observation: &zimascope_common::model::DomainObservation,
        now_instant: Instant,
        now_system: SystemTime,
    ) -> bool {
        let observed_at = instant_to_system(observation.observed_at, now_instant, now_system);
        let expires_at = instant_to_system(observation.expires_at, now_instant, now_system);
        if expires_at <= now_system {
            return false;
        }

        let domain = normalize_domain(&observation.domain);
        if domain.is_empty() {
            return false;
        }

        let key = ObservationKey {
            domain: domain.into_boxed_str(),
            address: observation.address,
            evidence: observation.evidence,
        };

        match self.observations.get_mut(&key) {
            Some(record) => {
                record.last_observed = record.last_observed.max(observed_at);
                record.expires_at = record.expires_at.max(expires_at);
                record.confidence = best_confidence(record.confidence, observation.confidence);
            }
            None => {
                let record = ObservationRecord {
                    domain: key.domain.clone(),
                    evidence: observation.evidence,
                    confidence: observation.confidence,
                    last_observed: observed_at,
                    expires_at,
                };
                self.observations.insert(key.clone(), record);
                self.address_index
                    .entry(observation.address)
                    .or_default()
                    .push(key);
            }
        }

        true
    }

    fn observe_flow(&mut self, update: FlowUpdate, now_instant: Instant, now_system: SystemTime) {
        let id = flow_id(&update.key);
        let remote = remote_endpoint(&update.key).clone();
        let first_seen = instant_to_system(update.first_seen, now_instant, now_system);
        let last_seen = instant_to_system(update.last_seen, now_instant, now_system);
        let domains = associate_observations(
            &self.observations,
            &self.address_index,
            remote.address,
            now_system,
        );
        let profile = self.enricher.profile(remote.address);

        match self.flows.get_mut(&id) {
            Some(record) => {
                record.total = update.total;
                record.first_seen = record.first_seen.min(first_seen);
                record.last_seen = record.last_seen.max(last_seen);
                record.state = update.state;
                record.domains = domains;
                record.remote_profile = Some(profile);
            }
            None => {
                if self.flows.len() >= self.flow_capacity {
                    self.evict_oldest();
                }
                self.flows.insert(
                    id,
                    FlowRecord {
                        id,
                        key: update.key,
                        total: update.total,
                        first_seen,
                        last_seen,
                        state: update.state,
                        domains,
                        remote_profile: Some(profile),
                    },
                );
            }
        }
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .flows
            .iter()
            .min_by_key(|(_, record)| record.last_seen)
            .map(|(id, _)| *id);
        if let Some(id) = oldest {
            self.flows.remove(&id);
        }
    }

    fn add_buckets(&mut self, at: SystemTime, inbound: TrafficCounters, outbound: TrafficCounters) {
        push_bucket(
            &mut self.minute_buckets,
            truncate_time(at, Duration::from_secs(60)),
            inbound,
            outbound,
            MINUTE_BUCKET_CAPACITY,
        );
        push_bucket(
            &mut self.hour_buckets,
            truncate_time(at, Duration::from_secs(3600)),
            inbound,
            outbound,
            HOUR_BUCKET_CAPACITY,
        );
    }

    // ------------------------------------------------------------------ reads

    pub(crate) fn list_flows(&self, query: &FlowListQuery) -> Result<Page<FlowDto>, ApiError> {
        let now = SystemTime::now();
        let filter = query.filter();
        let spec = parse_sort(
            query.sort.as_deref(),
            FlowSort::LastSeen,
            FlowSort::parse,
            true,
        )?;
        let cursor = query.cursor.as_deref().map(FlowCursor::parse).transpose()?;
        if let Some(cursor) = &cursor {
            if cursor.spec != spec {
                return Err(ApiError::bad_request(
                    "cursor does not match the requested sort order",
                ));
            }
        }
        let limit = page_limit(query.limit)?;

        let mut records = self.selected_flows(&filter, now);
        sort_flow_records(&mut records, spec);
        let total = records.len();

        if let Some(cursor) = &cursor {
            records.retain(|record| flow_after(record, cursor, spec));
        }
        let has_more = records.len() > limit;
        records.truncate(limit);
        let next_cursor = if has_more {
            records.last().map(|record| flow_cursor(record, spec))
        } else {
            None
        };

        Ok(Page {
            items: records
                .iter()
                .map(|record| flow_dto(record, &self.interfaces))
                .collect(),
            total,
            next_cursor,
        })
    }

    pub(crate) fn get_flow(&self, id: &str) -> Result<FlowDto, ApiError> {
        let id = u64::from_str_radix(id, 16)
            .map_err(|_| ApiError::bad_request(format!("invalid Flow id: {id}")))?;
        let record = self
            .flows
            .get(&id)
            .ok_or_else(|| ApiError::not_found(format!("no Flow with id {id:016x}")))?;
        Ok(flow_dto(record, &self.interfaces))
    }

    pub(crate) fn list_endpoints(
        &self,
        query: &EndpointListQuery,
    ) -> Result<Page<EndpointSummaryDto>, ApiError> {
        let now = SystemTime::now();
        let filter = query.filter();
        let spec = parse_sort(
            query.sort.as_deref(),
            EndpointSort::Bytes,
            EndpointSort::parse,
            true,
        )?;
        let cursor = query
            .cursor
            .as_deref()
            .map(EndpointCursor::parse)
            .transpose()?;
        if let Some(cursor) = &cursor {
            if cursor.spec != spec {
                return Err(ApiError::bad_request(
                    "cursor does not match the requested sort order",
                ));
            }
        }
        let limit = page_limit(query.limit)?;

        let mut aggregates = self.aggregate_endpoints(&filter, now);
        if let Some(has_domain) = filter.has_domain {
            aggregates.retain(|aggregate| !aggregate.domains.is_empty() == has_domain);
        }
        sort_endpoint_aggregates(&mut aggregates, spec);
        let total = aggregates.len();

        if let Some(cursor) = &cursor {
            aggregates.retain(|aggregate| endpoint_after(aggregate, cursor, spec));
        }
        let has_more = aggregates.len() > limit;
        aggregates.truncate(limit);
        let next_cursor = if has_more {
            aggregates
                .last()
                .map(|aggregate| endpoint_cursor(aggregate, spec))
        } else {
            None
        };

        Ok(Page {
            items: aggregates.iter().map(endpoint_summary_dto).collect(),
            total,
            next_cursor,
        })
    }

    pub(crate) fn get_endpoint(&self, address: &str) -> Result<EndpointDetailDto, ApiError> {
        let address: IpAddr = address
            .parse()
            .map_err(|_| ApiError::bad_request(format!("invalid IP address: {address}")))?;
        let now = SystemTime::now();

        let mut matched: Vec<&FlowRecord> = self
            .flows
            .values()
            .filter(|record| remote_endpoint(&record.key).address == address)
            .collect();
        if matched.is_empty() {
            return Err(ApiError::not_found(format!(
                "no Flow observed for endpoint {address}"
            )));
        }
        matched.sort_by_key(|record| std::cmp::Reverse(record.last_seen));

        let profile = matched
            .iter()
            .find_map(|record| record.remote_profile.clone())
            .unwrap_or_else(|| Arc::new(scope_only_profile(address, now)));

        let mut packets = 0u64;
        let mut bytes = 0u64;
        let mut first_seen = matched[0].first_seen;
        let mut last_seen = matched[0].last_seen;
        let mut domains: Vec<DomainAssociation> = Vec::new();
        let mut ports: HashMap<(u16, Protocol, FlowDirection), PortUsage> = HashMap::new();

        for record in &matched {
            packets = packets.saturating_add(record.total.packets);
            bytes = bytes.saturating_add(record.total.bytes);
            first_seen = first_seen.min(record.first_seen);
            last_seen = last_seen.max(record.last_seen);
            for association in &record.domains {
                push_domain(&mut domains, association);
            }

            let remote = remote_endpoint(&record.key);
            let Some(port) = remote.port else { continue };
            let entry = ports
                .entry((port, record.key.protocol, record.key.direction))
                .or_insert(PortUsage {
                    port,
                    protocol: record.key.protocol,
                    direction: record.key.direction,
                    packets: 0,
                    bytes: 0,
                    flow_count: 0,
                });
            entry.packets = entry.packets.saturating_add(record.total.packets);
            entry.bytes = entry.bytes.saturating_add(record.total.bytes);
            entry.flow_count += 1;
        }

        let mut ports: Vec<PortUsageDto> = ports
            .into_values()
            .map(|usage| PortUsageDto {
                port: usage.port,
                protocol: protocol_name(usage.protocol),
                direction: direction_name(usage.direction),
                packets: usage.packets,
                bytes: usage.bytes,
                flow_count: usage.flow_count,
            })
            .collect();
        ports.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then(a.port.cmp(&b.port))
                .then(a.protocol.cmp(b.protocol))
        });

        domains.sort_by(|a, b| a.domain.cmp(&b.domain));

        Ok(EndpointDetailDto {
            address: address.to_string(),
            profile: profile_dto(&profile),
            packets,
            bytes,
            flow_count: matched.len() as u64,
            first_seen: unix_millis(first_seen),
            last_seen: unix_millis(last_seen),
            ports,
            domains: domains.iter().map(domain_ref_dto).collect(),
            flows_url: format!(
                "/v1/flows?ip={}",
                encode_uri_component(&address.to_string())
            ),
        })
    }

    pub(crate) fn list_domains(
        &self,
        query: &DomainListQuery,
    ) -> Result<Page<DomainSummaryDto>, ApiError> {
        let now = SystemTime::now();
        let filter = query.filter();
        let spec = parse_sort(
            query.sort.as_deref(),
            DomainSort::Bytes,
            DomainSort::parse,
            true,
        )?;
        let cursor = query
            .cursor
            .as_deref()
            .map(DomainCursor::parse)
            .transpose()?;
        if let Some(cursor) = &cursor {
            if cursor.spec != spec {
                return Err(ApiError::bad_request(
                    "cursor does not match the requested sort order",
                ));
            }
        }
        let limit = page_limit(query.limit)?;

        let mut aggregates: Vec<DomainAggregate> =
            self.aggregate_domains(&filter, now).into_values().collect();

        if let Some(evidence) = query.evidence {
            aggregates.retain(|aggregate| {
                aggregate
                    .evidence_flows
                    .iter()
                    .any(|(kind, _)| evidence.matches(*kind))
            });
        }
        if let Some(confidence) = query.confidence {
            aggregates.retain(|aggregate| {
                aggregate
                    .confidence
                    .is_some_and(|value| confidence.matches(value))
            });
        }

        sort_domain_aggregates(&mut aggregates, spec);
        let total = aggregates.len();

        if let Some(cursor) = &cursor {
            aggregates.retain(|aggregate| domain_after(aggregate, cursor, spec));
        }
        let has_more = aggregates.len() > limit;
        aggregates.truncate(limit);
        let next_cursor = if has_more {
            aggregates
                .last()
                .map(|aggregate| domain_cursor(aggregate, spec))
        } else {
            None
        };

        Ok(Page {
            items: aggregates.iter().map(domain_summary_dto).collect(),
            total,
            next_cursor,
        })
    }

    pub(crate) fn get_domain(&self, domain: &str) -> Result<DomainDetailDto, ApiError> {
        let domain = normalize_domain(domain);
        if domain.is_empty() {
            return Err(ApiError::bad_request("domain must not be empty"));
        }
        let now = SystemTime::now();
        let aggregates = self.aggregate_domains(&FlowFilter::default(), now);
        let aggregate = aggregates.get(&domain).ok_or_else(|| {
            ApiError::not_found(format!("no Flow associated with domain {domain}"))
        })?;

        let mut addresses: Vec<DomainAddressDto> = aggregate
            .addresses
            .iter()
            .map(|(address, entry)| DomainAddressDto {
                address: address.to_string(),
                evidence: entry
                    .evidence
                    .iter()
                    .map(|kind| evidence_name(*kind))
                    .collect(),
                confidence: confidence_name(entry.confidence),
                country: entry
                    .profile
                    .as_ref()
                    .and_then(|profile| profile.country.as_ref().map(ToString::to_string)),
                asn: entry.profile.as_ref().and_then(|profile| profile.asn),
                organization: entry
                    .profile
                    .as_ref()
                    .and_then(|profile| profile.organization.as_ref().map(ToString::to_string)),
                bytes: entry.bytes,
                last_seen: unix_millis(entry.last_seen),
            })
            .collect();
        addresses.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.address.cmp(&b.address)));

        let mut countries: HashMap<String, (u64, u64)> = HashMap::new();
        let mut asns: HashMap<u32, (Option<String>, u64, u64)> = HashMap::new();
        for entry in aggregate.addresses.values() {
            if let Some(profile) = &entry.profile {
                if let Some(country) = &profile.country {
                    let value = countries.entry(country.to_string()).or_default();
                    value.0 = value.0.saturating_add(entry.bytes);
                    value.1 += 1;
                }
                if let Some(asn) = profile.asn {
                    let value = asns.entry(asn).or_insert_with(|| {
                        (profile.organization.as_ref().map(ToString::to_string), 0, 0)
                    });
                    value.1 = value.1.saturating_add(entry.bytes);
                    value.2 += 1;
                }
            }
        }

        let mut countries: Vec<CountryCountDto> = countries
            .into_iter()
            .map(|(country, (bytes, flows))| CountryCountDto {
                country,
                bytes,
                flows,
            })
            .collect();
        countries.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.country.cmp(&b.country)));

        let mut asns: Vec<AsnCountDto> = asns
            .into_iter()
            .map(|(asn, (organization, bytes, flows))| AsnCountDto {
                asn,
                organization,
                bytes,
                flows,
            })
            .collect();
        asns.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.asn.cmp(&b.asn)));

        Ok(DomainDetailDto {
            domain: aggregate.domain.clone(),
            packets: aggregate.packets,
            bytes: aggregate.bytes,
            flow_count: aggregate.flow_count,
            first_seen: unix_millis(aggregate.first_seen),
            last_seen: unix_millis(aggregate.last_seen),
            evidence: aggregate
                .evidence_flows
                .iter()
                .map(|(kind, flows)| EvidenceCountDto {
                    evidence: evidence_name(*kind),
                    flows: *flows,
                })
                .collect(),
            addresses,
            countries,
            asns,
            flows_url: format!("/v1/flows?domain={}", encode_uri_component(&domain)),
        })
    }

    pub(crate) fn overview(&self, range: TimeRange, now: SystemTime) -> OverviewDto {
        let filter = FlowFilter {
            range: Some(range),
            ..FlowFilter::default()
        };
        let flows = self.selected_flows(&filter, now);

        let mut totals = DirectionTotalsDto::default();
        let mut active_flows = 0u64;
        let mut flows_with_domain = 0u64;
        for record in &flows {
            match record.key.direction {
                FlowDirection::Inbound => add_dto_counters(&mut totals.inbound, record.total),
                FlowDirection::Outbound => add_dto_counters(&mut totals.outbound, record.total),
            }
            if matches!(record.state, FlowState::Active) {
                active_flows += 1;
            }
            if !record.domains.is_empty() {
                flows_with_domain += 1;
            }
        }

        let flows_total = flows.len() as u64;
        let ratio = if flows_total == 0 {
            0.0
        } else {
            flows_with_domain as f64 / flows_total as f64
        };

        OverviewDto {
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
            timeline: self.timeline(range, now),
            top_endpoints: self.top_endpoints(&filter, now),
            top_domains: self.top_domains(&filter, now),
            top_countries: self.top_countries(&flows),
            top_asns: self.top_asns(&flows),
            active_flows,
            domain_visibility: DomainVisibilityDto {
                flows_with_domain,
                flows_total,
                ratio,
            },
            health: self.health.as_ref().map(CollectorHealthDto::from_health),
        }
    }

    // --------------------------------------------------------------- exports

    pub(crate) fn create_export(
        &mut self,
        request: &CreateExportRequest,
    ) -> Result<ExportTaskDto, ApiError> {
        let now = SystemTime::now();
        let filter = &request.filter;

        let (content, content_type, record_count, truncated) = match request.format {
            ExportFormat::Json => {
                let document = self.export_document(filter, now);
                let record_count = document.flows.len() as u64;
                let truncated = document.truncated;
                let bytes = serde_json::to_vec_pretty(&document)
                    .map_err(|error| ApiError::internal(format!("serialize export: {error}")))?;
                (
                    bytes,
                    ExportFormat::Json.content_type(),
                    record_count,
                    truncated,
                )
            }
            ExportFormat::Csv => {
                let (csv, record_count, truncated) = self.export_csv(filter, now);
                (
                    csv.into_bytes(),
                    ExportFormat::Csv.content_type(),
                    record_count,
                    truncated,
                )
            }
        };

        self.export_counter += 1;
        let id = format!("exp-{}", self.export_counter);
        let expires_at = now.checked_add(self.export_ttl).unwrap_or(now);
        let record = ExportRecord {
            id,
            format: request.format,
            range: request.filter.range,
            created_at: now,
            expires_at,
            record_count,
            truncated,
            content_type,
            content,
        };
        let dto = record.dto(now);
        self.exports.push_front(record);
        self.audit("export.create", "completed");
        Ok(dto)
    }

    pub(crate) fn list_exports(&self) -> Vec<ExportTaskDto> {
        let now = SystemTime::now();
        self.exports.iter().map(|record| record.dto(now)).collect()
    }

    pub(crate) fn get_export(&self, id: &str) -> Result<ExportTaskDto, ApiError> {
        let record = self
            .exports
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| ApiError::not_found(format!("no export with id {id}")))?;
        Ok(record.dto(SystemTime::now()))
    }

    pub(crate) fn export_content(&self, id: &str) -> Result<ExportContent, ApiError> {
        let record = self
            .exports
            .iter()
            .find(|record| record.id == id)
            .ok_or_else(|| ApiError::not_found(format!("no export with id {id}")))?;
        if SystemTime::now() >= record.expires_at {
            return Err(ApiError::gone(format!(
                "export {id} content has expired and was discarded"
            )));
        }
        Ok(ExportContent {
            content_type: record.content_type,
            file_name: format!(
                "zimascope-export-{}.{}",
                record.id,
                record.format.extension()
            ),
            bytes: record.content.clone(),
        })
    }

    pub(crate) fn delete_export(&mut self, id: &str) -> Result<(), ApiError> {
        let Some(position) = self.exports.iter().position(|record| record.id == id) else {
            return Err(ApiError::not_found(format!("no export with id {id}")));
        };
        self.exports.remove(position);
        self.audit("export.delete", "completed");
        Ok(())
    }

    fn export_document(&self, filter: &FlowFilter, now: SystemTime) -> ExportDocument {
        let (records, truncated) = self.export_records(filter, now);

        let mut profiles: Vec<IpProfileDto> = Vec::new();
        let mut seen_profiles = HashSet::new();
        for record in &records {
            if let Some(profile) = &record.remote_profile {
                if seen_profiles.insert(profile.address) {
                    profiles.push(profile_dto(profile));
                }
            }
        }

        let mut domains: Vec<DomainSummaryDto> = self
            .aggregate_domains(filter, now)
            .values()
            .map(domain_summary_dto)
            .collect();
        domains.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.domain.cmp(&b.domain)));
        domains.truncate(EXPORT_MAX_RECORDS);

        ExportDocument {
            generated_at: unix_millis(now),
            range: filter.range.map(TimeRange::as_str),
            truncated,
            flows: records
                .iter()
                .map(|record| flow_dto(record, &self.interfaces))
                .collect(),
            domains,
            profiles,
            health: self.health.as_ref().map(CollectorHealthDto::from_health),
        }
    }

    fn export_csv(&self, filter: &FlowFilter, now: SystemTime) -> (String, u64, bool) {
        let (records, truncated) = self.export_records(filter, now);
        let mut csv = String::from(CSV_HEADER);
        for record in &records {
            let remote = remote_endpoint(&record.key);
            let (domain, evidence, confidence) = record
                .domains
                .first()
                .map(|association| {
                    (
                        association.domain.as_ref(),
                        evidence_name(association.evidence),
                        confidence_name(association.confidence),
                    )
                })
                .unwrap_or(("", "", ""));
            let interface = self
                .interfaces
                .get(&record.key.interface_index.get())
                .map(Box::as_ref)
                .unwrap_or("");
            let _ = writeln!(
                csv,
                "{:016x},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
                record.id,
                direction_name(record.key.direction),
                protocol_name(record.key.protocol),
                state_name(record.state),
                match record.state {
                    FlowState::Ended(reason) => end_reason_name(reason),
                    FlowState::Active => "",
                },
                record.key.source.address,
                optional_port(record.key.source.port),
                record.key.destination.address,
                optional_port(record.key.destination.port),
                remote.address,
                optional_port(remote.port),
                csv_field(interface),
                record.total.packets,
                record.total.bytes,
                unix_millis(record.first_seen),
                unix_millis(record.last_seen),
                csv_field(domain),
                evidence,
                confidence,
            );
        }
        (csv, records.len() as u64, truncated)
    }

    fn export_records(&self, filter: &FlowFilter, now: SystemTime) -> (Vec<&FlowRecord>, bool) {
        let mut records = self.selected_flows(filter, now);
        let spec = SortSpec {
            field: FlowSort::LastSeen,
            descending: true,
        };
        sort_flow_records(&mut records, spec);
        let truncated = records.len() > EXPORT_MAX_RECORDS;
        records.truncate(EXPORT_MAX_RECORDS);
        (records, truncated)
    }

    // -------------------------------------------------------------- lifecycle

    pub(crate) fn clear_history(&mut self) {
        self.flows.clear();
        self.observations.clear();
        self.address_index.clear();
        self.minute_buckets.clear();
        self.hour_buckets.clear();
        self.exports.clear();
        self.rates = Rates::default();
        self.audit("history.clear", "completed");
    }

    pub(crate) fn set_flow_capacity(&mut self, capacity: usize) {
        self.flow_capacity = capacity.max(1);
        while self.flows.len() > self.flow_capacity {
            self.evict_oldest();
        }
    }

    pub(crate) fn apply_settings(&mut self, settings: &Settings) {
        self.set_flow_capacity(settings.resources.max_flow_entries as usize);
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

    // ------------------------------------------------------------- internals

    fn selected_flows(&self, filter: &FlowFilter, now: SystemTime) -> Vec<&FlowRecord> {
        let cutoff = filter.range.map(|range| range.cutoff(now));
        let query = filter
            .q
            .as_deref()
            .map(|q| q.trim().to_ascii_lowercase())
            .filter(|q| !q.is_empty());
        self.flows
            .values()
            .filter(|record| {
                flow_matches(record, filter, cutoff, query.as_deref(), &self.interfaces)
            })
            .collect()
    }

    fn aggregate_endpoints(&self, filter: &FlowFilter, now: SystemTime) -> Vec<EndpointAggregate> {
        let mut flow_filter = filter.clone();
        flow_filter.has_domain = None;

        let mut aggregates: HashMap<IpAddr, EndpointAggregate> = HashMap::new();
        for record in self.selected_flows(&flow_filter, now) {
            let remote = remote_endpoint(&record.key);
            let aggregate = aggregates
                .entry(remote.address)
                .or_insert_with(|| EndpointAggregate {
                    address: remote.address,
                    address_string: remote.address.to_string(),
                    profile: record.remote_profile.clone(),
                    packets: 0,
                    bytes: 0,
                    flow_count: 0,
                    first_seen: record.first_seen,
                    last_seen: record.last_seen,
                    domains: Vec::new(),
                });
            aggregate.packets = aggregate.packets.saturating_add(record.total.packets);
            aggregate.bytes = aggregate.bytes.saturating_add(record.total.bytes);
            aggregate.flow_count += 1;
            aggregate.first_seen = aggregate.first_seen.min(record.first_seen);
            aggregate.last_seen = aggregate.last_seen.max(record.last_seen);
            for association in &record.domains {
                push_domain(&mut aggregate.domains, association);
            }
        }

        aggregates.into_values().collect()
    }

    fn aggregate_domains(
        &self,
        filter: &FlowFilter,
        now: SystemTime,
    ) -> HashMap<String, DomainAggregate> {
        let mut flow_filter = filter.clone();
        flow_filter.has_domain = None;

        let mut aggregates: HashMap<String, DomainAggregate> = HashMap::new();
        for record in self.selected_flows(&flow_filter, now) {
            let remote = remote_endpoint(&record.key);
            for association in &record.domains {
                let aggregate = aggregates
                    .entry(association.domain.to_string())
                    .or_insert_with(|| DomainAggregate {
                        domain: association.domain.to_string(),
                        packets: 0,
                        bytes: 0,
                        flow_count: 0,
                        first_seen: record.first_seen,
                        last_seen: record.last_seen,
                        evidence_flows: Vec::new(),
                        confidence: None,
                        addresses: HashMap::new(),
                    });
                aggregate.packets = aggregate.packets.saturating_add(record.total.packets);
                aggregate.bytes = aggregate.bytes.saturating_add(record.total.bytes);
                aggregate.flow_count += 1;
                aggregate.first_seen = aggregate.first_seen.min(record.first_seen);
                aggregate.last_seen = aggregate.last_seen.max(record.last_seen);
                aggregate.confidence = Some(
                    aggregate
                        .confidence
                        .map(|current| best_confidence(current, association.confidence))
                        .unwrap_or(association.confidence),
                );

                match aggregate
                    .evidence_flows
                    .iter_mut()
                    .find(|(kind, _)| *kind == association.evidence)
                {
                    Some((_, flows)) => *flows += 1,
                    None => aggregate.evidence_flows.push((association.evidence, 1)),
                }

                let address = aggregate
                    .addresses
                    .entry(remote.address)
                    .or_insert_with(|| DomainAddressAggregate {
                        evidence: Vec::new(),
                        confidence: association.confidence,
                        profile: record.remote_profile.clone(),
                        packets: 0,
                        bytes: 0,
                        last_seen: record.last_seen,
                    });
                address.packets = address.packets.saturating_add(record.total.packets);
                address.bytes = address.bytes.saturating_add(record.total.bytes);
                address.last_seen = address.last_seen.max(record.last_seen);
                address.confidence = best_confidence(address.confidence, association.confidence);
                if !address.evidence.contains(&association.evidence) {
                    address.evidence.push(association.evidence);
                }
            }
        }

        aggregates
    }

    fn top_endpoints(&self, filter: &FlowFilter, now: SystemTime) -> Vec<EndpointSummaryDto> {
        let mut aggregates = self.aggregate_endpoints(filter, now);
        sort_endpoint_aggregates(
            &mut aggregates,
            SortSpec {
                field: EndpointSort::Bytes,
                descending: true,
            },
        );
        aggregates.truncate(TOP_LIST_LIMIT);
        aggregates.iter().map(endpoint_summary_dto).collect()
    }

    fn top_domains(&self, filter: &FlowFilter, now: SystemTime) -> Vec<DomainSummaryDto> {
        let mut aggregates: Vec<DomainAggregate> =
            self.aggregate_domains(filter, now).into_values().collect();
        sort_domain_aggregates(
            &mut aggregates,
            SortSpec {
                field: DomainSort::Bytes,
                descending: true,
            },
        );
        aggregates.truncate(TOP_LIST_LIMIT);
        aggregates.iter().map(domain_summary_dto).collect()
    }

    fn top_countries(&self, flows: &[&FlowRecord]) -> Vec<CountryCountDto> {
        let mut countries: HashMap<String, (u64, u64)> = HashMap::new();
        for record in flows {
            if let Some(profile) = &record.remote_profile {
                if let Some(country) = &profile.country {
                    let value = countries.entry(country.to_string()).or_default();
                    value.0 = value.0.saturating_add(record.total.bytes);
                    value.1 += 1;
                }
            }
        }
        let mut list: Vec<CountryCountDto> = countries
            .into_iter()
            .map(|(country, (bytes, flows))| CountryCountDto {
                country,
                bytes,
                flows,
            })
            .collect();
        list.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.country.cmp(&b.country)));
        list.truncate(TOP_LIST_LIMIT);
        list
    }

    fn top_asns(&self, flows: &[&FlowRecord]) -> Vec<AsnCountDto> {
        let mut asns: HashMap<u32, (Option<String>, u64, u64)> = HashMap::new();
        for record in flows {
            if let Some(profile) = &record.remote_profile {
                if let Some(asn) = profile.asn {
                    let value = asns.entry(asn).or_insert_with(|| {
                        (profile.organization.as_ref().map(ToString::to_string), 0, 0)
                    });
                    value.1 = value.1.saturating_add(record.total.bytes);
                    value.2 += 1;
                }
            }
        }
        let mut list: Vec<AsnCountDto> = asns
            .into_iter()
            .map(|(asn, (organization, bytes, flows))| AsnCountDto {
                asn,
                organization,
                bytes,
                flows,
            })
            .collect();
        list.sort_by(|a, b| b.bytes.cmp(&a.bytes).then(a.asn.cmp(&b.asn)));
        list.truncate(TOP_LIST_LIMIT);
        list
    }

    fn timeline(&self, range: TimeRange, now: SystemTime) -> TimelineDto {
        let (resolution, buckets, step) = match range {
            TimeRange::Minute15 | TimeRange::Hour1 => {
                ("minute", &self.minute_buckets, Duration::from_secs(60))
            }
            TimeRange::Hour24 | TimeRange::Day7 => {
                ("hour", &self.hour_buckets, Duration::from_secs(3600))
            }
        };

        let step_ms = step.as_millis() as i64;
        let end_ms = unix_millis(now).div_euclid(step_ms) * step_ms;
        let start_ms = unix_millis(range.cutoff(now)).div_euclid(step_ms) * step_ms;

        let mut by_start: HashMap<i64, &Bucket> = HashMap::new();
        for bucket in buckets {
            by_start.insert(unix_millis(bucket.start), bucket);
        }

        let mut points = Vec::new();
        let mut at = start_ms;
        while at <= end_ms && points.len() < MAX_TIMELINE_POINTS {
            let (inbound, outbound) = by_start
                .get(&at)
                .map(|bucket| {
                    (
                        CountersDto {
                            packets: bucket.inbound.packets,
                            bytes: bucket.inbound.bytes,
                        },
                        CountersDto {
                            packets: bucket.outbound.packets,
                            bytes: bucket.outbound.bytes,
                        },
                    )
                })
                .unwrap_or_default();
            points.push(TimelinePointDto {
                start: at,
                inbound,
                outbound,
            });
            at += step_ms;
        }

        TimelineDto { resolution, points }
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

struct PortUsage {
    port: u16,
    protocol: Protocol,
    direction: FlowDirection,
    packets: u64,
    bytes: u64,
    flow_count: u64,
}

// ------------------------------------------------------------------ helpers

fn flow_id(key: &FlowKey) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    key.hash(&mut hasher);
    hasher.finish()
}

fn remote_endpoint(key: &FlowKey) -> &Endpoint {
    match key.direction {
        FlowDirection::Inbound => &key.source,
        FlowDirection::Outbound => &key.destination,
    }
}

fn endpoint_dto(endpoint: &Endpoint) -> EndpointDto {
    EndpointDto {
        address: endpoint.address.to_string(),
        port: endpoint.port,
    }
}

fn flow_dto(record: &FlowRecord, interfaces: &HashMap<u32, Box<str>>) -> FlowDto {
    let remote = remote_endpoint(&record.key).address;
    let profile = record
        .remote_profile
        .clone()
        .unwrap_or_else(|| Arc::new(scope_only_profile(remote, SystemTime::now())));

    FlowDto {
        id: format!("{:016x}", record.id),
        direction: direction_name(record.key.direction),
        protocol: protocol_name(record.key.protocol),
        state: state_name(record.state),
        end_reason: match record.state {
            FlowState::Ended(reason) => Some(end_reason_name(reason)),
            FlowState::Active => None,
        },
        source: endpoint_dto(&record.key.source),
        destination: endpoint_dto(&record.key.destination),
        remote: endpoint_dto(remote_endpoint(&record.key)),
        remote_profile: profile_dto(&profile),
        interface: interfaces
            .get(&record.key.interface_index.get())
            .map(ToString::to_string),
        packets: record.total.packets,
        bytes: record.total.bytes,
        first_seen: unix_millis(record.first_seen),
        last_seen: unix_millis(record.last_seen),
        duration_ms: record
            .last_seen
            .duration_since(record.first_seen)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0),
        domains: record.domains.iter().map(domain_ref_dto).collect(),
    }
}

fn domain_ref_dto(association: &DomainAssociation) -> DomainRefDto {
    DomainRefDto {
        domain: association.domain.to_string(),
        evidence: evidence_name(association.evidence),
        confidence: confidence_name(association.confidence),
    }
}

fn profile_dto(profile: &IpProfile) -> IpProfileDto {
    IpProfileDto {
        address: profile.address.to_string(),
        scope: scope_name(profile.scope),
        country: profile.country.as_ref().map(ToString::to_string),
        region: profile.region.as_ref().map(ToString::to_string),
        city_approximate: profile.city_approximate.as_ref().map(ToString::to_string),
        asn: profile.asn,
        organization: profile.organization.as_ref().map(ToString::to_string),
        database_version: profile.database_version.as_ref().map(ToString::to_string),
        enriched_at: unix_millis(profile.enriched_at),
    }
}

fn scope_only_profile(address: IpAddr, enriched_at: SystemTime) -> IpProfile {
    IpProfile {
        address,
        scope: AddressScope::classify(address),
        country: None,
        region: None,
        city_approximate: None,
        asn: None,
        organization: None,
        database_version: None,
        enriched_at,
    }
}

fn endpoint_summary_dto(aggregate: &EndpointAggregate) -> EndpointSummaryDto {
    let profile = aggregate.profile.as_deref();
    EndpointSummaryDto {
        address: aggregate.address.to_string(),
        scope: scope_name(
            profile
                .map(|profile| profile.scope)
                .unwrap_or_else(|| AddressScope::classify(aggregate.address)),
        ),
        country: profile.and_then(|profile| profile.country.as_ref().map(ToString::to_string)),
        region: profile.and_then(|profile| profile.region.as_ref().map(ToString::to_string)),
        asn: profile.and_then(|profile| profile.asn),
        organization: profile
            .and_then(|profile| profile.organization.as_ref().map(ToString::to_string)),
        packets: aggregate.packets,
        bytes: aggregate.bytes,
        flow_count: aggregate.flow_count,
        first_seen: unix_millis(aggregate.first_seen),
        last_seen: unix_millis(aggregate.last_seen),
        domains: aggregate
            .domains
            .iter()
            .take(MAX_DOMAIN_CANDIDATES)
            .map(|association| association.domain.to_string())
            .collect(),
    }
}

fn domain_summary_dto(aggregate: &DomainAggregate) -> DomainSummaryDto {
    DomainSummaryDto {
        domain: aggregate.domain.clone(),
        packets: aggregate.packets,
        bytes: aggregate.bytes,
        flow_count: aggregate.flow_count,
        first_seen: unix_millis(aggregate.first_seen),
        last_seen: unix_millis(aggregate.last_seen),
        evidence: aggregate
            .evidence_flows
            .iter()
            .map(|(kind, _)| evidence_name(*kind))
            .collect(),
    }
}

fn push_domain(domains: &mut Vec<DomainAssociation>, association: &DomainAssociation) {
    if let Some(existing) = domains
        .iter_mut()
        .find(|existing| existing.domain == association.domain)
    {
        if evidence_rank(association.evidence) > evidence_rank(existing.evidence) {
            existing.evidence = association.evidence;
        }
        existing.confidence = best_confidence(existing.confidence, association.confidence);
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

fn best_confidence(
    current: AssociationConfidence,
    candidate: AssociationConfidence,
) -> AssociationConfidence {
    match (current, candidate) {
        (AssociationConfidence::Direct, _) | (_, AssociationConfidence::Direct) => {
            AssociationConfidence::Direct
        }
        _ => AssociationConfidence::Inferred,
    }
}

fn associate_observations(
    observations: &HashMap<ObservationKey, ObservationRecord>,
    index: &HashMap<IpAddr, Vec<ObservationKey>>,
    address: IpAddr,
    now: SystemTime,
) -> Vec<DomainAssociation> {
    let Some(keys) = index.get(&address) else {
        return Vec::new();
    };

    let mut candidates: Vec<&ObservationRecord> = keys
        .iter()
        .filter_map(|key| observations.get(key))
        .filter(|record| record.expires_at > now)
        .collect();
    candidates.sort_by(|a, b| {
        evidence_rank(b.evidence)
            .cmp(&evidence_rank(a.evidence))
            .then(b.last_observed.cmp(&a.last_observed))
            .then(b.domain.cmp(&a.domain))
    });

    let mut domains: Vec<DomainAssociation> = Vec::new();
    for candidate in candidates {
        if domains
            .iter()
            .any(|domain| domain.domain == candidate.domain)
        {
            continue;
        }
        domains.push(DomainAssociation {
            domain: candidate.domain.clone(),
            evidence: candidate.evidence,
            confidence: candidate.confidence,
        });
        if domains.len() >= MAX_DOMAIN_CANDIDATES {
            break;
        }
    }
    domains
}

fn flow_matches(
    record: &FlowRecord,
    filter: &FlowFilter,
    cutoff: Option<SystemTime>,
    query: Option<&str>,
    interfaces: &HashMap<u32, Box<str>>,
) -> bool {
    if let Some(cutoff) = cutoff {
        if record.last_seen < cutoff {
            return false;
        }
    }
    if let Some(query) = query {
        if !flow_search_text(record, interfaces).contains(query) {
            return false;
        }
    }
    if let Some(direction) = filter.direction {
        if !direction.matches(record.key.direction) {
            return false;
        }
    }
    if let Some(protocol) = filter.protocol {
        if !protocol.matches(record.key.protocol) {
            return false;
        }
    }
    if let Some(ip) = filter.ip {
        if record.key.source.address != ip && record.key.destination.address != ip {
            return false;
        }
    }
    if let Some(src_ip) = filter.src_ip {
        if record.key.source.address != src_ip {
            return false;
        }
    }
    if let Some(dst_ip) = filter.dst_ip {
        if record.key.destination.address != dst_ip {
            return false;
        }
    }
    if let Some(port) = filter.port {
        if record.key.source.port != Some(port) && record.key.destination.port != Some(port) {
            return false;
        }
    }
    if let Some(state) = filter.state {
        if !state.matches(record.state) {
            return false;
        }
    }
    if let Some(domain) = &filter.domain {
        let domain = normalize_domain(domain);
        if !record
            .domains
            .iter()
            .any(|association| association.domain.as_ref() == domain)
        {
            return false;
        }
    }
    if let Some(has_domain) = filter.has_domain {
        if record.domains.is_empty() == has_domain {
            return false;
        }
    }

    let profile = record.remote_profile.as_deref();
    if let Some(scope) = filter.scope {
        let scope_value = profile
            .map(|profile| profile.scope)
            .unwrap_or_else(|| AddressScope::classify(remote_endpoint(&record.key).address));
        if !scope.matches(scope_value) {
            return false;
        }
    }
    if let Some(country) = &filter.country {
        let matches = profile
            .and_then(|profile| profile.country.as_deref())
            .is_some_and(|value| value.eq_ignore_ascii_case(country));
        if !matches {
            return false;
        }
    }
    if let Some(asn) = filter.asn {
        if profile.and_then(|profile| profile.asn) != Some(asn) {
            return false;
        }
    }
    if let Some(organization) = &filter.organization {
        let organization = organization.to_ascii_lowercase();
        let matches = profile
            .and_then(|profile| profile.organization.as_deref())
            .is_some_and(|value| value.to_ascii_lowercase().contains(&organization));
        if !matches {
            return false;
        }
    }

    true
}

/// Lowercase searchable text of a Flow, matching the fields used by the
/// generic `q` filter on lists, exports and the SSE stream.
fn flow_search_text(record: &FlowRecord, interfaces: &HashMap<u32, Box<str>>) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(160);
    let _ = write!(
        text,
        "{:016x} {} {} {} ",
        record.id,
        direction_name(record.key.direction),
        protocol_name(record.key.protocol),
        state_name(record.state)
    );
    if let FlowState::Ended(reason) = record.state {
        let _ = write!(text, "{} ", end_reason_name(reason));
    }
    let _ = write!(text, "{} ", record.key.source.address);
    if let Some(port) = record.key.source.port {
        let _ = write!(text, "{port} ");
    }
    let _ = write!(text, "{} ", record.key.destination.address);
    if let Some(port) = record.key.destination.port {
        let _ = write!(text, "{port} ");
    }
    if let Some(interface) = interfaces.get(&record.key.interface_index.get()) {
        let _ = write!(text, "{interface} ");
    }
    for association in &record.domains {
        let _ = write!(text, "{} ", association.domain);
    }
    text.make_ascii_lowercase();
    text
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SortSpec<F> {
    field: F,
    descending: bool,
}

fn parse_sort<F: Copy>(
    raw: Option<&str>,
    default: F,
    parse: fn(&str) -> Option<F>,
    default_descending: bool,
) -> Result<SortSpec<F>, ApiError> {
    match raw {
        None => Ok(SortSpec {
            field: default,
            descending: default_descending,
        }),
        Some(raw) => {
            let (raw_field, descending) = match raw.strip_prefix('-') {
                Some(field) => (field, true),
                None => (raw.strip_prefix('+').unwrap_or(raw), false),
            };
            let field = parse(raw_field).ok_or_else(|| {
                ApiError::bad_request(format!("unsupported sort field: {raw_field:?}"))
            })?;
            Ok(SortSpec { field, descending })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlowSort {
    LastSeen,
    FirstSeen,
    Bytes,
    Packets,
}

impl FlowSort {
    const fn name(self) -> &'static str {
        match self {
            Self::LastSeen => "last_seen",
            Self::FirstSeen => "first_seen",
            Self::Bytes => "bytes",
            Self::Packets => "packets",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "last_seen" => Some(Self::LastSeen),
            "first_seen" => Some(Self::FirstSeen),
            "bytes" => Some(Self::Bytes),
            "packets" => Some(Self::Packets),
            _ => None,
        }
    }
}

fn canonical_sort<F>(spec: SortSpec<F>, parse_name: fn(F) -> &'static str) -> String {
    format!(
        "{}{}",
        if spec.descending { "-" } else { "" },
        parse_name(spec.field)
    )
}

fn flow_sort_value(record: &FlowRecord, field: FlowSort) -> u64 {
    match field {
        FlowSort::LastSeen => unix_millis(record.last_seen).max(0) as u64,
        FlowSort::FirstSeen => unix_millis(record.first_seen).max(0) as u64,
        FlowSort::Bytes => record.total.bytes,
        FlowSort::Packets => record.total.packets,
    }
}

fn sort_flow_records(records: &mut [&FlowRecord], spec: SortSpec<FlowSort>) {
    records.sort_by(|a, b| {
        let ordering = flow_sort_value(a, spec.field)
            .cmp(&flow_sort_value(b, spec.field))
            .then(a.id.cmp(&b.id));
        if spec.descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn flow_cursor(record: &FlowRecord, spec: SortSpec<FlowSort>) -> String {
    format!(
        "{}:{}:{:016x}",
        canonical_sort(spec, FlowSort::name),
        flow_sort_value(record, spec.field),
        record.id
    )
}

struct FlowCursor {
    spec: SortSpec<FlowSort>,
    value: u64,
    id: u64,
}

impl FlowCursor {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        let mut parts = raw.splitn(3, ':');
        let sort = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;
        let value = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;
        let id = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;

        let spec = parse_sort(Some(sort), FlowSort::LastSeen, FlowSort::parse, true)?;
        let value = value
            .parse::<u64>()
            .map_err(|_| ApiError::bad_request("invalid cursor"))?;
        let id =
            u64::from_str_radix(id, 16).map_err(|_| ApiError::bad_request("invalid cursor"))?;
        Ok(Self { spec, value, id })
    }
}

fn flow_after(record: &FlowRecord, cursor: &FlowCursor, spec: SortSpec<FlowSort>) -> bool {
    tuple_after(
        flow_sort_value(record, spec.field),
        record.id,
        cursor.value,
        cursor.id,
        spec.descending,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointSort {
    Bytes,
    Packets,
    LastSeen,
}

impl EndpointSort {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "bytes" => Some(Self::Bytes),
            "packets" => Some(Self::Packets),
            "last_seen" => Some(Self::LastSeen),
            _ => None,
        }
    }
}

impl EndpointSort {
    const fn name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Packets => "packets",
            Self::LastSeen => "last_seen",
        }
    }
}

fn endpoint_sort_value(aggregate: &EndpointAggregate, field: EndpointSort) -> u64 {
    match field {
        EndpointSort::Bytes => aggregate.bytes,
        EndpointSort::Packets => aggregate.packets,
        EndpointSort::LastSeen => unix_millis(aggregate.last_seen).max(0) as u64,
    }
}

fn sort_endpoint_aggregates(aggregates: &mut [EndpointAggregate], spec: SortSpec<EndpointSort>) {
    aggregates.sort_by(|a, b| {
        let ordering = endpoint_sort_value(a, spec.field)
            .cmp(&endpoint_sort_value(b, spec.field))
            .then(a.address_string.cmp(&b.address_string));
        if spec.descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn endpoint_cursor(aggregate: &EndpointAggregate, spec: SortSpec<EndpointSort>) -> String {
    format!(
        "{}:{}:{}",
        canonical_sort(spec, EndpointSort::name),
        endpoint_sort_value(aggregate, spec.field),
        aggregate.address_string
    )
}

struct EndpointCursor {
    spec: SortSpec<EndpointSort>,
    value: u64,
    address: String,
}

impl EndpointCursor {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        let mut parts = raw.splitn(3, ':');
        let sort = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;
        let value = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;
        let address = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;

        let spec = parse_sort(Some(sort), EndpointSort::Bytes, EndpointSort::parse, true)?;
        let value = value
            .parse::<u64>()
            .map_err(|_| ApiError::bad_request("invalid cursor"))?;
        Ok(Self {
            spec,
            value,
            address: address.to_owned(),
        })
    }
}

fn endpoint_after(
    aggregate: &EndpointAggregate,
    cursor: &EndpointCursor,
    spec: SortSpec<EndpointSort>,
) -> bool {
    tuple_after(
        endpoint_sort_value(aggregate, spec.field),
        aggregate.address_string.as_str(),
        cursor.value,
        cursor.address.as_str(),
        spec.descending,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DomainSort {
    Bytes,
    Packets,
    LastSeen,
    Domain,
}

impl DomainSort {
    const fn name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Packets => "packets",
            Self::LastSeen => "last_seen",
            Self::Domain => "domain",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "bytes" => Some(Self::Bytes),
            "packets" => Some(Self::Packets),
            "last_seen" => Some(Self::LastSeen),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }
}

fn domain_sort_value(aggregate: &DomainAggregate, field: DomainSort) -> u64 {
    match field {
        DomainSort::Bytes => aggregate.bytes,
        DomainSort::Packets => aggregate.packets,
        DomainSort::LastSeen => unix_millis(aggregate.last_seen).max(0) as u64,
        DomainSort::Domain => 0,
    }
}

fn sort_domain_aggregates(aggregates: &mut [DomainAggregate], spec: SortSpec<DomainSort>) {
    aggregates.sort_by(|a, b| {
        let ordering = domain_sort_value(a, spec.field)
            .cmp(&domain_sort_value(b, spec.field))
            .then(a.domain.cmp(&b.domain));
        if spec.descending {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn domain_cursor(aggregate: &DomainAggregate, spec: SortSpec<DomainSort>) -> String {
    format!(
        "{}:{}:{}",
        canonical_sort(spec, DomainSort::name),
        domain_sort_value(aggregate, spec.field),
        aggregate.domain
    )
}

struct DomainCursor {
    spec: SortSpec<DomainSort>,
    value: u64,
    domain: String,
}

impl DomainCursor {
    fn parse(raw: &str) -> Result<Self, ApiError> {
        let mut parts = raw.splitn(3, ':');
        let sort = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;
        let value = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;
        let domain = parts
            .next()
            .ok_or_else(|| ApiError::bad_request("invalid cursor"))?;

        let spec = parse_sort(Some(sort), DomainSort::Bytes, DomainSort::parse, true)?;
        let value = value
            .parse::<u64>()
            .map_err(|_| ApiError::bad_request("invalid cursor"))?;
        Ok(Self {
            spec,
            value,
            domain: domain.to_owned(),
        })
    }
}

fn domain_after(
    aggregate: &DomainAggregate,
    cursor: &DomainCursor,
    spec: SortSpec<DomainSort>,
) -> bool {
    tuple_after(
        domain_sort_value(aggregate, spec.field),
        aggregate.domain.as_str(),
        cursor.value,
        cursor.domain.as_str(),
        spec.descending,
    )
}

fn tuple_after<T: PartialOrd>(
    value: u64,
    tie: T,
    cursor_value: u64,
    cursor_tie: T,
    descending: bool,
) -> bool {
    let less = value < cursor_value || (value == cursor_value && tie < cursor_tie);
    let greater = value > cursor_value || (value == cursor_value && tie > cursor_tie);
    if descending { less } else { greater }
}

fn add_counters(target: &mut TrafficCounters, delta: TrafficCounters) {
    target.packets = target.packets.saturating_add(delta.packets);
    target.bytes = target.bytes.saturating_add(delta.bytes);
}

fn add_dto_counters(target: &mut CountersDto, delta: TrafficCounters) {
    target.packets = target.packets.saturating_add(delta.packets);
    target.bytes = target.bytes.saturating_add(delta.bytes);
}

fn push_bucket(
    buckets: &mut VecDeque<Bucket>,
    start: SystemTime,
    inbound: TrafficCounters,
    outbound: TrafficCounters,
    capacity: usize,
) {
    match buckets.back_mut() {
        Some(last) if last.start == start => {
            add_counters(&mut last.inbound, inbound);
            add_counters(&mut last.outbound, outbound);
            return;
        }
        Some(last) if last.start < start => {
            buckets.push_back(Bucket {
                start,
                inbound,
                outbound,
            });
        }
        _ => {
            if let Some(position) = buckets.iter().position(|bucket| bucket.start == start) {
                let bucket = &mut buckets[position];
                add_counters(&mut bucket.inbound, inbound);
                add_counters(&mut bucket.outbound, outbound);
            } else {
                let position = buckets
                    .iter()
                    .position(|bucket| bucket.start > start)
                    .unwrap_or(buckets.len());
                buckets.insert(
                    position,
                    Bucket {
                        start,
                        inbound,
                        outbound,
                    },
                );
            }
        }
    }
    while buckets.len() > capacity {
        buckets.pop_front();
    }
}

fn truncate_time(time: SystemTime, step: Duration) -> SystemTime {
    let seconds = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let step = step.as_secs().max(1);
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds / step * step)
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
