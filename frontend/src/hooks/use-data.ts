/**
 * TanStack Query bindings over the data facade (`store.ts`): caching and
 * background refresh. Live ticks bypass the cache and are consumed through
 * `useTick`.
 */

import { keepPreviousData, useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { data, onResync } from "@/store";
import type { FlowQuery } from "@/api";
import type { SettingsPatch, TimeRange } from "@/types";

export const queryKeys = {
  overview: (range: TimeRange, excludeScope?: string) => ["overview", range, excludeScope ?? ""] as const,
  flows: (query: FlowQuery) => ["flows", query] as const,
  connectionsPage: (query: FlowQuery) => ["connections-page", query] as const,
  flow: (id: string) => ["flow", id] as const,
  endpoints: (query: FlowQuery) => ["endpoints", query] as const,
  endpointsPage: (query: FlowQuery) => ["endpoints-page", query] as const,
  endpoint: (address: string) => ["endpoint", address] as const,
  endpointTimeline: (address: string, range: TimeRange) => ["endpoint-timeline", address, range] as const,
  domains: (query: FlowQuery) => ["domains", query] as const,
  domainsPage: (query: FlowQuery) => ["domains-page", query] as const,
  domain: (name: string) => ["domain", name] as const,
  domainTimeline: (name: string, range: TimeRange) => ["domain-timeline", name, range] as const,
  applications: (query: FlowQuery) => ["applications", query] as const,
  applicationsPage: (query: FlowQuery) => ["applications-page", query] as const,
  application: (id: string) => ["application", id] as const,
  applicationTimeline: (id: string, range: TimeRange) => ["application-timeline", id, range] as const,
  status: () => ["status"] as const,
  settings: () => ["settings"] as const,
  exports: () => ["exports"] as const,
};

/** Reloads REST state whenever the live stream reports a resync. */
export function useStreamResync(): void {
  const queryClient = useQueryClient();
  useEffect(
    () =>
      onResync(() => {
        void queryClient.invalidateQueries();
      }),
    [queryClient],
  );
}

export function useOverview(range: TimeRange, excludeScope?: string) {
  return useQuery({
    queryKey: queryKeys.overview(range, excludeScope),
    queryFn: () => data.overview(range, excludeScope),
    staleTime: 15_000,
  });
}

export function useFlows(query: FlowQuery) {
  return useQuery({
    queryKey: queryKeys.flows(query),
    queryFn: () => data.flows(query),
    placeholderData: keepPreviousData,
  });
}

/** Merged connection list, loaded page by page while scrolling. */
export function useConnectionsInfinite(query: FlowQuery) {
  return useInfiniteQuery({
    queryKey: queryKeys.connectionsPage(query),
    queryFn: ({ pageParam }) => data.connections({ ...query, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: nextPageParam,
    placeholderData: keepPreviousData,
  });
}

export function useFlow(id: string | null) {
  return useQuery({
    queryKey: queryKeys.flow(id ?? ""),
    queryFn: () => data.flow(id!),
    enabled: Boolean(id),
  });
}

export function useEndpoints(query: FlowQuery) {
  return useQuery({
    queryKey: queryKeys.endpoints(query),
    queryFn: () => data.endpoints(query),
    placeholderData: keepPreviousData,
  });
}

export function useEndpointsInfinite(query: FlowQuery) {
  return useInfiniteQuery({
    queryKey: queryKeys.endpointsPage(query),
    queryFn: ({ pageParam }) => data.endpoints({ ...query, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: nextPageParam,
    placeholderData: keepPreviousData,
  });
}

export function useEndpoint(address: string | null) {
  return useQuery({
    queryKey: queryKeys.endpoint(address ?? ""),
    queryFn: () => data.endpoint(address!),
    enabled: Boolean(address),
  });
}

export function useEndpointTimeline(address: string | null, range: TimeRange) {
  return useQuery({
    queryKey: queryKeys.endpointTimeline(address ?? "", range),
    queryFn: () => data.endpointTimeline(address!, range),
    enabled: Boolean(address),
  });
}

export function useDomains(query: FlowQuery) {
  return useQuery({
    queryKey: queryKeys.domains(query),
    queryFn: () => data.domains(query),
    placeholderData: keepPreviousData,
  });
}

export function useDomainsInfinite(query: FlowQuery) {
  return useInfiniteQuery({
    queryKey: queryKeys.domainsPage(query),
    queryFn: ({ pageParam }) => data.domains({ ...query, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: nextPageParam,
    placeholderData: keepPreviousData,
  });
}

/** Next offset for an offset-paginated page, or `undefined` at the end. */
function nextPageParam(last: { items: unknown[]; total: number; offset: number }): number | undefined {
  const next = last.offset + last.items.length;
  return last.items.length > 0 && next < last.total ? next : undefined;
}

export function useDomain(name: string | null) {
  return useQuery({
    queryKey: queryKeys.domain(name ?? ""),
    queryFn: () => data.domain(name!),
    enabled: Boolean(name),
  });
}

export function useDomainTimeline(name: string | null, range: TimeRange) {
  return useQuery({
    queryKey: queryKeys.domainTimeline(name ?? "", range),
    queryFn: () => data.domainTimeline(name!, range),
    enabled: Boolean(name),
  });
}

export function useApplications(query: FlowQuery) {
  return useQuery({
    queryKey: queryKeys.applications(query),
    queryFn: () => data.applications(query),
    placeholderData: keepPreviousData,
  });
}

export function useApplicationsInfinite(query: FlowQuery) {
  return useInfiniteQuery({
    queryKey: queryKeys.applicationsPage(query),
    queryFn: ({ pageParam }) => data.applications({ ...query, offset: pageParam }),
    initialPageParam: 0,
    getNextPageParam: nextPageParam,
    placeholderData: keepPreviousData,
  });
}

export function useApplication(id: string | null) {
  return useQuery({
    queryKey: queryKeys.application(id ?? ""),
    queryFn: () => data.application(id!),
    enabled: Boolean(id),
  });
}

export function useApplicationTimeline(id: string | null, range: TimeRange) {
  return useQuery({
    queryKey: queryKeys.applicationTimeline(id ?? "", range),
    queryFn: () => data.applicationTimeline(id!, range),
    enabled: Boolean(id),
  });
}

export function useStatus() {
  return useQuery({
    queryKey: queryKeys.status(),
    queryFn: () => data.status(),
    staleTime: 10_000,
  });
}

export function useSettings() {
  return useQuery({
    queryKey: queryKeys.settings(),
    queryFn: () => data.settings(),
    staleTime: 30_000,
  });
}

export function useSaveSettings() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (patch: SettingsPatch) => data.saveSettings(patch),
    onSuccess: (settings) => {
      queryClient.setQueryData(queryKeys.settings(), settings);
      queryClient.invalidateQueries({ queryKey: queryKeys.status() });
    },
  });
}

export function useClearHistory() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => data.clearHistory(),
    onSuccess: () => queryClient.invalidateQueries(),
  });
}

export function useExports() {
  return useQuery({
    queryKey: queryKeys.exports(),
    queryFn: () => data.exports(),
    staleTime: 5_000,
  });
}

export function useCreateExport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (request: Parameters<typeof data.createExport>[0]) => data.createExport(request),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.exports() }),
  });
}

export function useDeleteExport() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => data.deleteExport(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: queryKeys.exports() }),
  });
}
