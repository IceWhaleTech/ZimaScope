// Wire types mirroring the local API DTOs (zimascoped/src/api/dto.rs).

export type Direction = "inbound" | "outbound";
export type Protocol = "tcp" | "udp";
export type FlowState = "active" | "ended";
export type Evidence = "dns" | "tls_sni" | "http_host";
export type Confidence = "direct" | "inferred";
export type Scope =
  | "public"
  | "private"
  | "shared"
  | "fake_ip"
  | "loopback"
  | "link_local"
  | "unique_local"
  | "multicast"
  | "broadcast"
  | "documentation"
  | "reserved"
  | "unspecified";
export type CollectorState = "running" | "degraded" | "stopped";
export type TimeRange = "15m" | "1h" | "24h" | "7d";
export type ExportFormat = "json" | "csv";

/** Offset-paginated collection envelope. */
export interface Page<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface Endpoint {
  address: string;
  port: number | null;
}

export interface IpProfile {
  address: string;
  scope: Scope;
  country: string | null;
  region: string | null;
  city_approximate: string | null;
  asn: number | null;
  organization: string | null;
  database_version: string | null;
  enriched_at: number;
}

export interface DomainRef {
  domain: string;
  evidence: Evidence;
  confidence: Confidence;
}

/** Application Identity attached to a Flow when socket ownership was observed. */
export interface ApplicationRef {
  id: string;
  name: string;
  kind: "process" | "container";
}

export interface Flow {
  id: string;
  direction: Direction;
  protocol: Protocol;
  state: FlowState;
  end_reason: string | null;
  source: Endpoint;
  destination: Endpoint;
  remote: Endpoint;
  remote_profile: IpProfile;
  interface: string | null;
  packets: number;
  bytes: number;
  first_seen: number;
  last_seen: number;
  duration_ms: number;
  domains: DomainRef[];
  application: ApplicationRef | null;
}

/**
 * Both directions of a Flow merged into one record. Connection identity is
 * the unordered endpoint pair, so a TCP exchange appears once with
 * directional counters instead of twice as directional Flows.
 */
export interface Connection {
  id: string;
  protocol: Protocol;
  /** Fingerprint library match (`SSH`, `MySQL`, `TLS`, …); null means the
      UI falls back to plain TCP/UDP. */
  service: string | null;
  state: FlowState;
  end_reason: string | null;
  /** The device's side of the connection. */
  host: Endpoint;
  /** The peer side: the remote for outbound connections, the client for inbound ones. */
  remote: Endpoint;
  remote_profile: IpProfile;
  interface: string | null;
  packets: number;
  bytes: number;
  /** Directional counters relative to the Device Boundary. */
  traffic: DirectionTotals;
  first_seen: number;
  last_seen: number;
  duration_ms: number;
  domains: DomainRef[];
}

export interface EndpointSummary {
  address: string;
  scope: Scope;
  country: string | null;
  region: string | null;
  asn: number | null;
  organization: string | null;
  packets: number;
  bytes: number;
  traffic: DirectionTotals;
  flow_count: number;
  first_seen: number;
  last_seen: number;
}

export interface PortUsage {
  port: number;
  protocol: Protocol;
  direction: Direction;
  packets: number;
  bytes: number;
  flow_count: number;
}

export interface EndpointDetail {
  address: string;
  profile: IpProfile;
  packets: number;
  bytes: number;
  flow_count: number;
  first_seen: number;
  last_seen: number;
  ports: PortUsage[];
  domains: DomainRef[];
  flows_url: string;
}

/** One Application Identity with its traffic over the requested window. */
export interface ApplicationSummary {
  id: string;
  name: string;
  kind: "process" | "container";
  exe: string | null;
  comm: string | null;
  uid: number | null;
  container_id: string | null;
  packets: number;
  bytes: number;
  traffic: DirectionTotals;
  flow_count: number;
  first_seen: number;
  last_seen: number;
}

export interface ApplicationDetail {
  id: string;
  name: string;
  kind: "process" | "container";
  exe: string | null;
  comm: string | null;
  uid: number | null;
  container_id: string | null;
  packets: number;
  bytes: number;
  traffic: DirectionTotals;
  flow_count: number;
  first_seen: number;
  last_seen: number;
  domains: DomainRef[];
  /** Peer addresses with the Associated Domains observed for each. */
  destinations: ApplicationDestination[];
  flows_url: string;
}

export interface ApplicationDestination {
  address: string;
  scope: Scope;
  country: string | null;
  asn: number | null;
  organization: string | null;
  packets: number;
  bytes: number;
  traffic: DirectionTotals;
  flow_count: number;
  domains: DomainRef[];
}

export interface EvidenceCount {
  evidence: Evidence;
  flows: number;
}

export interface DomainSummary {
  domain: string;
  packets: number;
  bytes: number;
  traffic: DirectionTotals;
  flow_count: number;
  first_seen: number;
  last_seen: number;
  evidence: Evidence[];
}

export interface DomainAddress {
  address: string;
  evidence: Evidence[];
  confidence: Confidence;
  country: string | null;
  asn: number | null;
  organization: string | null;
  bytes: number;
  first_seen: number;
  last_seen: number;
}

export interface CountryCount {
  country: string;
  bytes: number;
  flows: number;
}

export interface AsnCount {
  asn: number;
  organization: string | null;
  bytes: number;
  flows: number;
}

export interface DomainDetail {
  domain: string;
  packets: number;
  bytes: number;
  flow_count: number;
  first_seen: number;
  last_seen: number;
  evidence: EvidenceCount[];
  addresses: DomainAddress[];
  countries: CountryCount[];
  asns: AsnCount[];
  flows_url: string;
}

export interface Counters {
  packets: number;
  bytes: number;
}

export interface Rates {
  inbound_bps: number;
  outbound_bps: number;
}

export interface DirectionTotals {
  inbound: Counters;
  outbound: Counters;
}

export interface TimelinePoint {
  start: number;
  inbound: Counters;
  outbound: Counters;
}

export interface ProxiedTraffic {
  flows: number;
  bytes: number;
  flows_with_domain: number;
  /** Fake-IP flows whose real destination was resolved via the proxy API. */
  resolved_flows: number;
}

export interface Timeline {
  resolution: "minute" | "hour";
  points: TimelinePoint[];
}

export interface DomainVisibility {
  flows_with_domain: number;
  flows_total: number;
  ratio: number;
  by_evidence: EvidenceCount[];
}

export interface InterfaceHealth {
  ifindex: number;
  name: string;
  ingress_attached: boolean;
  egress_attached: boolean;
  last_error: string | null;
}

export interface MapUsage {
  entries: number;
  capacity: number;
}

export interface KernelCounters {
  packets_seen: number;
  packets_parsed: number;
  parse_failures: number;
  map_update_failures: number;
  flow_evictions: number;
  domain_events_emitted: number;
  domain_events_dropped: number;
  service_events_emitted: number;
  service_events_dropped: number;
  owner_events_inserted: number;
  owner_events_dropped: number;
  policy_dropped_packets: number;
  policy_dropped_bytes: number;
  policy_missing_state: number;
}

export interface ObservationGap {
  kind: "interface_detached" | "map_read_failed";
  ifindex: number | null;
  started_at: number;
  ended_at: number | null;
}

export interface ApplicationHealth {
  attached: boolean;
  udp_attached: boolean;
  last_error: string | null;
}

export interface CollectorHealth {
  state: CollectorState;
  interfaces: InterfaceHealth[];
  map: MapUsage;
  kernel: KernelCounters;
  gaps: ObservationGap[];
  application: ApplicationHealth;
}

export interface Overview {
  range: TimeRange;
  generated_at: number;
  rates: Rates;
  totals: DirectionTotals;
  timeline: Timeline;
  top_endpoints: EndpointSummary[];
  top_domains: DomainSummary[];
  top_countries: CountryCount[];
  top_asns: AsnCount[];
  active_flows: number;
  domain_visibility: DomainVisibility;
  /** Fake-IP traffic terminated by the local proxy; geography not observable. */
  proxied: ProxiedTraffic;
  health: CollectorHealth | null;
}

export interface EnrichmentStatus {
  database_version: string | null;
  loaded_at: number | null;
  error: string | null;
}

export interface AuditEntry {
  at: number;
  action: string;
  outcome: string;
}

export interface SettingsSummary {
  enabled: boolean;
  boundary_interfaces: string[];
  domain_observation: boolean;
  history_enabled: boolean;
  retention_days: number;
}

export interface FingerprintStatus {
  rules: number;
  custom: boolean;
}

export interface ProxyStatus {
  enabled: boolean;
  reachable: boolean;
  mapped: number;
  last_error: string | null;
}

export interface ServiceStatus {
  service: "starting" | "running" | "degraded" | "stopped" | "unavailable";
  version: string;
  api_version: string;
  started_at: number;
  uptime_seconds: number;
  last_batch_at: number | null;
  batch_sequence: number;
  collector_error: string | null;
  database_error: string | null;
  collector: CollectorHealth | null;
  enrichment: EnrichmentStatus;
  fingerprints: FingerprintStatus;
  proxy: ProxyStatus;
  enforcement: EnforcementStatus;
  settings: SettingsSummary;
  recent_operations: AuditEntry[];
}

export type RuleAction = "limit" | "block";
export type RuleDirection = "inbound" | "outbound" | "both";
/** Derived enforcement state of one rule. */
export type RuleState = "active" | "unresolved" | "bypassed" | "unavailable";

export interface EnforcementStatus {
  enabled: boolean;
  available: boolean;
  revision: number;
  rules_total: number;
  rules_active: number;
  rules_unresolved: number;
  dropped_packets: number;
  dropped_bytes: number;
  last_error: string | null;
}

export interface TrafficRuleMatch {
  kind: "endpoint" | "cidr" | "application";
  address: string | null;
  prefix_len: number | null;
  port: number | null;
  application_id: string | null;
}

export interface TrafficRuleCounters {
  matched_packets: number;
  matched_bytes: number;
  dropped_packets: number;
  dropped_bytes: number;
}

export interface TrafficRule {
  id: number;
  action: RuleAction;
  direction: RuleDirection;
  match: TrafficRuleMatch;
  rate_bytes_per_s: number;
  burst_bytes: number;
  enabled: boolean;
  state: RuleState;
  state_reason: string | null;
  created_at: number;
  updated_at: number;
  counters: TrafficRuleCounters | null;
}

export interface TrafficRuleMatchInput {
  kind: "endpoint" | "cidr" | "application";
  address?: string;
  prefix_len?: number;
  port?: number;
  application_id?: string;
}

export interface CreateTrafficRuleRequest {
  action: RuleAction;
  direction: RuleDirection;
  match: TrafficRuleMatchInput;
  rate_bytes_per_s?: number;
  enabled?: boolean;
}

export interface UpdateTrafficRuleRequest {
  action?: RuleAction;
  direction?: RuleDirection;
  match?: TrafficRuleMatchInput;
  rate_bytes_per_s?: number;
  enabled?: boolean;
}

export interface BoundarySettings {
  /** Empty means "follow the default route". */
  interfaces: string[];
}

export interface DomainObservationSettings {
  enabled: boolean;
  dns: boolean;
  tls_sni: boolean;
  http_host: boolean;
}

export interface HistorySettings {
  enabled: boolean;
  retention_days: number;
}

export interface ResourceSettings {
  max_flow_entries: number;
  disk_quota_mb: number;
}

export interface ProxySettings {
  enabled: boolean;
  /** e.g. `http://192.168.100.3:9090` (http only). */
  controller_url: string;
  secret: string;
}

export interface Settings {
  enabled: boolean;
  boundary: BoundarySettings;
  domains: DomainObservationSettings;
  history: HistorySettings;
  resources: ResourceSettings;
  proxy: ProxySettings;
  traffic_rules: TrafficRuleSettings;
}

export interface TrafficRuleSettings {
  enabled: boolean;
}

export interface SettingsPatch {
  enabled?: boolean;
  boundary?: Partial<BoundarySettings>;
  domains?: Partial<DomainObservationSettings>;
  history?: Partial<HistorySettings>;
  resources?: Partial<ResourceSettings>;
  proxy?: Partial<ProxySettings>;
  traffic_rules?: Partial<TrafficRuleSettings>;
}

export interface ExportTask {
  id: string;
  status: "completed" | "expired";
  format: ExportFormat;
  range: TimeRange | null;
  created_at: number;
  expires_at: number;
  record_count: number;
  size_bytes: number;
  truncated: boolean;
  content_type: string;
  download_url: string;
}

export interface DomainObservation {
  domain: string;
  address: string;
  evidence: Evidence;
  confidence: Confidence;
  observed_at: number;
}

/** Live counters over all retained history, sent with every tick. */
export interface TickOverview {
  active_flows: number;
  flows_total: number;
  flows_with_domain: number;
  ratio: number;
}

/** One collection interval pushed over `/v1/stream` (`event: tick`). */
export interface Tick {
  sequence: number;
  collected_at: number;
  interval_ms: number;
  traffic: Rates & { inbound: Counters; outbound: Counters };
  flows: Flow[];
  /** Refreshed aggregates for every peer touched by this interval. */
  endpoints: EndpointSummary[];
  /** Refreshed aggregates for every Associated Domain touched. */
  domains: DomainSummary[];
  /** Refreshed aggregates for every Application touched. */
  applications: ApplicationSummary[];
  observations: DomainObservation[];
  overview: TickOverview;
  health: CollectorHealth | null;
}
