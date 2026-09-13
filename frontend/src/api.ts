// Typed client for the local ZimaScope API (Unix socket, behind the ZimaOS
// reverse proxy or the Vite dev proxy).

import type {
  ApplicationDetail,
  ApplicationSummary,
  CollectorHealth,
  Connection,
  DomainDetail,
  DomainSummary,
  EndpointDetail,
  EndpointSummary,
  Evidence,
  ExportFormat,
  ExportTask,
  Flow,
  Overview,
  Page,
  CreateTrafficRuleRequest,
  ResolveTrafficRuleRequest,
  ResolveTrafficRuleResponse,
  ServiceStatus,
  Settings,
  SettingsPatch,
  Timeline,
  TimeRange,
  TrafficRule,
  UpdateTrafficRuleRequest,
} from "./types";

/** RFC 9457 problem details raised by the API. */
export class ApiError extends Error {
  readonly status: number;
  readonly title: string;

  constructor(status: number, title: string, detail: string) {
    super(detail);
    this.name = "ApiError";
    this.status = status;
    this.title = title;
  }
}

interface ProblemDetails {
  title?: string;
  detail?: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    let problem: ProblemDetails = {};
    try {
      problem = (await response.json()) as ProblemDetails;
    } catch {
      // Non-JSON error body; fall back to the status line.
    }
    throw new ApiError(
      response.status,
      problem.title ?? response.statusText,
      problem.detail ?? `HTTP ${response.status}`,
    );
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

function json(method: string, body: unknown): RequestInit {
  return {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  };
}

/** Shared filters accepted by `/v1/flows`, `/v1/endpoints` and `/v1/domains`. */
export interface FlowQuery {
  q?: string;
  range?: TimeRange;
  /** Absolute window (Unix epoch ms); only with `end`, and never with `range`. */
  start?: number;
  end?: number;
  direction?: string;
  protocol?: string;
  /** Fingerprint service name (`SSH`, `TLS`, `HTTP`, …). */
  service?: string;
  ip?: string;
  src_ip?: string;
  dst_ip?: string;
  port?: number;
  domain?: string;
  /** Application Identity key (`proc:<exe>` or `cont:<container id>`). */
  application_id?: string;
  country?: string;
  asn?: number;
  organization?: string;
  /** Comma-separated scopes to show, matched against the remote address. */
  scope?: string;
  /** Comma-separated scopes to hide, matched against the remote address. */
  exclude_scope?: string;
  state?: string;
  has_domain?: boolean;
  evidence?: Evidence;
  confidence?: string;
  /** Connection listings only: collapse DNS and sub-second chatter. */
  hide_noise?: boolean;
  sort?: string;
  limit?: number;
  offset?: number;
}

export function queryString(query: object): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  return params.toString();
}

export function fetchFlows(query: FlowQuery = {}): Promise<Page<Flow>> {
  return request(`/v1/flows?${queryString(query)}`);
}

export function fetchFlow(id: string): Promise<Flow> {
  return request(`/v1/flows/${encodeURIComponent(id)}`);
}

/** Both directions of each Flow merged into one connection record. */
export function fetchConnections(query: FlowQuery = {}): Promise<Page<Connection>> {
  return request(`/v1/connections?${queryString(query)}`);
}

export function fetchOverview(range: TimeRange = "15m", excludeScope?: string): Promise<Overview> {
  return request(`/v1/overview?${queryString({ range, exclude_scope: excludeScope })}`);
}

export function fetchStatus(): Promise<ServiceStatus> {
  return request("/v1/status");
}

export function fetchCollectorHealth(): Promise<CollectorHealth | null> {
  return fetchStatus().then((status) => status.collector);
}

export function fetchEndpoints(query: FlowQuery = {}): Promise<Page<EndpointSummary>> {
  return request(`/v1/endpoints?${queryString(query)}`);
}

export function fetchEndpoint(address: string): Promise<EndpointDetail> {
  return request(`/v1/endpoints/${encodeURIComponent(address)}`);
}

export function fetchEndpointTimeline(address: string, range: TimeRange = "15m"): Promise<Timeline> {
  return request(`/v1/endpoints/${encodeURIComponent(address)}/timeline?range=${range}`);
}

export function fetchDomains(query: FlowQuery = {}): Promise<Page<DomainSummary>> {
  return request(`/v1/domains?${queryString(query)}`);
}

export function fetchApplications(query: FlowQuery = {}): Promise<Page<ApplicationSummary>> {
  return request(`/v1/applications?${queryString(query)}`);
}

export function fetchApplication(id: string): Promise<ApplicationDetail> {
  return request(`/v1/applications/${encodeURIComponent(id)}`);
}

export function fetchApplicationTimeline(
  id: string,
  range: TimeRange = "15m",
): Promise<Timeline> {
  return request(`/v1/applications/${encodeURIComponent(id)}/timeline?range=${range}`);
}

export function fetchDomain(domain: string): Promise<DomainDetail> {
  return request(`/v1/domains/${encodeURIComponent(domain)}`);
}

export function fetchDomainTimeline(domain: string, range: TimeRange = "15m"): Promise<Timeline> {
  return request(`/v1/domains/${encodeURIComponent(domain)}/timeline?range=${range}`);
}

export function fetchSettings(): Promise<Settings> {
  return request("/v1/settings");
}

export function replaceSettings(settings: Settings): Promise<Settings> {
  return request("/v1/settings", json("PUT", settings));
}

export function patchSettings(patch: SettingsPatch): Promise<Settings> {
  return request("/v1/settings", json("PATCH", patch));
}

export interface CreateExportRequest extends FlowQuery {
  format?: ExportFormat;
}

export function createExport(exportRequest: CreateExportRequest = {}): Promise<ExportTask> {
  return request("/v1/exports", json("POST", exportRequest));
}

export function fetchExports(): Promise<ExportTask[]> {
  return request("/v1/exports");
}

export function fetchExport(id: string): Promise<ExportTask> {
  return request(`/v1/exports/${encodeURIComponent(id)}`);
}

/** Absolute URL of a completed export; browsers download it directly. */
export function exportContentUrl(id: string): string {
  return `/v1/exports/${encodeURIComponent(id)}/content`;
}

export function deleteExport(id: string): Promise<void> {
  return request(`/v1/exports/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function clearHistory(): Promise<void> {
  return request("/v1/history?confirm=true", { method: "DELETE" });
}

export function fetchTrafficRules(): Promise<TrafficRule[]> {
  return request("/v1/traffic-rules");
}

export function createTrafficRule(rule: CreateTrafficRuleRequest): Promise<TrafficRule> {
  return request("/v1/traffic-rules", json("POST", rule));
}

export function updateTrafficRule(id: number, rule: UpdateTrafficRuleRequest): Promise<TrafficRule> {
  return request(`/v1/traffic-rules/${id}`, json("PATCH", rule));
}

export function resolveTrafficRule(
  rule: ResolveTrafficRuleRequest,
): Promise<ResolveTrafficRuleResponse> {
  return request("/v1/traffic-rules/resolve", json("POST", rule));
}

export function deleteTrafficRule(id: number): Promise<void> {
  return request(`/v1/traffic-rules/${id}`, { method: "DELETE" });
}

export interface StreamQuery {
  q?: string;
  direction?: string;
  protocol?: string;
  ip?: string;
  src_ip?: string;
  dst_ip?: string;
  port?: number;
  domain?: string;
  application_id?: string;
  scope?: string;
  exclude_scope?: string;
  state?: string;
  has_domain?: boolean;
}

/** URL for `EventSource`; emits `tick` and `resync` events. */
export function streamUrl(query: StreamQuery = {}): string {
  const params = queryString(query);
  return params ? `/v1/stream?${params}` : "/v1/stream";
}

export async function fetchDashboard(query: FlowQuery): Promise<{
  flows: Page<Flow>;
  overview: Overview;
}> {
  const [flows, overview] = await Promise.all([
    fetchFlows({ ...query, limit: query.limit ?? 50 }),
    fetchOverview(query.range ?? "15m"),
  ]);
  return { flows, overview };
}
