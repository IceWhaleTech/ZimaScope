/**
 * Data facade plus the live tick subscription.
 *
 * Every read goes to the local agent; an unreachable agent rejects and the
 * views surface that state. There is deliberately no demo/fallback world:
 * fabricated data must never masquerade as observations.
 */

import * as api from "./api";
import type { CreateExportRequest, FlowQuery, StreamQuery } from "./api";
import type {
  ApplicationDetail,
  ApplicationSummary,
  Connection,
  DomainDetail,
  DomainSummary,
  EndpointDetail,
  EndpointSummary,
  ExportTask,
  Flow,
  Overview,
  Page,
  ServiceStatus,
  Settings,
  SettingsPatch,
  Tick,
  Timeline,
  TimeRange,
} from "./types";

const listeners = new Set<(tick: Tick) => void>();
const resyncListeners = new Set<() => void>();

let eventSource: EventSource | undefined;
let tickerStarted = false;
let streamQuery: StreamQuery = {};
/// Desired filter set (the key of `streamQuery`).
let streamQueryKey = "";
/// Filter set of the connection that is actually open.
let openQueryKey = "";
/// Delay before the last unsubscriber closes the stream, so view transitions
/// do not cancel and reopen the connection.
let stopTimer: number | undefined;

/** Notified when the stream reports `resync`: reload REST state. */
export function onResync(listener: () => void): () => void {
  resyncListeners.add(listener);
  return () => resyncListeners.delete(listener);
}

function notifyResync(): void {
  resyncListeners.forEach((listener) => listener());
}

function isNotFound(error: unknown): boolean {
  return error instanceof api.ApiError && error.status === 404;
}

export const data = {
  overview: (range: TimeRange, excludeScope?: string): Promise<Overview> =>
    api.fetchOverview(range, excludeScope),
  flows: (query: FlowQuery): Promise<Page<Flow>> => api.fetchFlows(query),
  connections: (query: FlowQuery): Promise<Page<Connection>> => api.fetchConnections(query),
  flow: async (id: string): Promise<Flow | null> => {
    try {
      return await api.fetchFlow(id);
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  },
  endpoints: (query: FlowQuery): Promise<Page<EndpointSummary>> => api.fetchEndpoints(query),
  endpoint: async (address: string): Promise<EndpointDetail | null> => {
    try {
      return await api.fetchEndpoint(address);
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  },
  endpointTimeline: (address: string, range: TimeRange): Promise<Timeline> =>
    api.fetchEndpointTimeline(address, range),
  domains: (query: FlowQuery): Promise<Page<DomainSummary>> => api.fetchDomains(query),
  domain: async (name: string): Promise<DomainDetail | null> => {
    try {
      return await api.fetchDomain(name);
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  },
  domainTimeline: (name: string, range: TimeRange): Promise<Timeline> =>
    api.fetchDomainTimeline(name, range),
  applications: (query: FlowQuery): Promise<Page<ApplicationSummary>> =>
    api.fetchApplications(query),
  application: async (id: string): Promise<ApplicationDetail | null> => {
    try {
      return await api.fetchApplication(id);
    } catch (error) {
      if (isNotFound(error)) return null;
      throw error;
    }
  },
  applicationTimeline: (id: string, range: TimeRange): Promise<Timeline> =>
    api.fetchApplicationTimeline(id, range),
  status: (): Promise<ServiceStatus> => api.fetchStatus(),
  settings: (): Promise<Settings> => api.fetchSettings(),
  saveSettings: (patch: SettingsPatch): Promise<Settings> => api.patchSettings(patch),
  clearHistory: (): Promise<void> => api.clearHistory(),
  exports: (): Promise<ExportTask[]> => api.fetchExports(),
  deleteExport: (id: string): Promise<void> => api.deleteExport(id),
  createExport: (request: CreateExportRequest = {}): Promise<ExportTask> =>
    api.createExport(request),
};

/**
 * Retargets the live stream to the given filters. The connection is
 * re-opened when the filter set actually changes; the backend rejects
 * filters it cannot evaluate on a live update.
 */
export function setStreamQuery(query: StreamQuery): void {
  const key = JSON.stringify(
    Object.fromEntries(
      Object.entries(query)
        .filter(([, value]) => value !== undefined && value !== null && value !== "")
        .sort(([left], [right]) => left.localeCompare(right)),
    ),
  );
  if (key === streamQueryKey) return;
  streamQueryKey = key;
  streamQuery = query;
  // Only re-open now when something is consuming ticks; otherwise the next
  // subscriber opens the stream with the new filters.
  if (tickerStarted && listeners.size > 0 && openQueryKey !== key) openStream();
}

/** Subscribe to live ticks. Returns an unsubscribe function. */
export function subscribeTicks(listener: (tick: Tick) => void): () => void {
  if (stopTimer !== undefined) {
    window.clearTimeout(stopTimer);
    stopTimer = undefined;
  }
  listeners.add(listener);
  ensureTicker();
  return () => {
    listeners.delete(listener);
    if (!listeners.size) {
      stopTimer = window.setTimeout(() => {
        stopTimer = undefined;
        if (!listeners.size) stopTicker();
      }, 2_000);
    }
  };
}

function ensureTicker(): void {
  if (tickerStarted) {
    // Reuse the open connection unless it carries stale filters.
    if (!eventSource || openQueryKey !== streamQueryKey) openStream();
    return;
  }
  tickerStarted = true;
  openStream();
}

function openStream(): void {
  eventSource?.close();
  const source = new EventSource(api.streamUrl(streamQuery));
  eventSource = source;
  openQueryKey = streamQueryKey;
  source.addEventListener("tick", (event) => {
    if (eventSource !== source) return;
    try {
      emit(JSON.parse((event as MessageEvent).data) as Tick);
    } catch {
      // Ignore malformed frames; the next tick re-syncs.
    }
  });
  source.addEventListener("resync", () => {
    if (eventSource === source) notifyResync();
  });
  // EventSource reconnects on its own; errors from a connection we already
  // replaced are ignored by the instance guards above.
}

function stopTicker(): void {
  eventSource?.close();
  eventSource = undefined;
  openQueryKey = "";
  tickerStarted = false;
}

function emit(tick: Tick): void {
  listeners.forEach((listener) => listener(tick));
}
