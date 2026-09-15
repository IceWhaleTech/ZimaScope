/**
 * Explorer — one table, four lenses. Connections, Endpoints, Domains and
 * Applications are the same observed traffic grouped differently, so a single
 * persistent table serves all four: the scope control re-targets the same
 * table and the header labels and body morph across with a short crossfade —
 * the frame never remounts. Scope lives in the URL (`?scope=`) so deep links
 * keep working. Connection rows fold into groups and are refreshed live;
 * interacting with a row or the search pauses live re-sorting (PRD 9.2).
 */

import { startTransition, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router";
import { ArrowDown, ArrowUp, ArrowUpDown, Download, Info, Loader2, Lock, Search, SlidersHorizontal, X } from "lucide-react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { toast } from "sonner";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TableCell, Table, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  ConnectionRows,
  CONNECTION_COLUMNS,
  flattenConnectionGroups,
  groupConnections,
} from "@/components/connection-table";
import { DomainRow, DOMAIN_COLUMNS } from "@/components/domain-table";
import { EmptyState } from "@/components/empty-state";
import { EndpointRow, ENDPOINT_COLUMNS } from "@/components/endpoint-table";
import { ApplicationRow, APPLICATION_COLUMNS } from "@/components/application-table";
import {
  InterfaceFilterControl,
  NetworkFilterControl,
  TimeFilter,
  type TimeWindow,
} from "@/components/filter-controls";
import { RowContextMenu } from "@/components/row-context-menu";
import { Segmented } from "@/components/segmented";
import { TableSkeleton } from "@/components/skeletons";
import { FOCUS_SEARCH_EVENT } from "@/components/app-layout";
import {
  useApplicationsInfinite,
  useConnectionsInfinite,
  useCreateExport,
  useDomainsInfinite,
  useEndpointsInfinite,
  useStatus,
} from "@/hooks/use-data";
import { useDetails } from "@/hooks/use-details";
import { useInterfaceFilter } from "@/hooks/use-interface-filter";
import { useNetworkFilter } from "@/hooks/use-network-filter";
import { useSetTopbar } from "@/hooks/use-topbar";
import { setStreamQuery, subscribeTicks } from "@/store";
import { excludeScopeParam, scopeParam as networkScopeParam } from "@/lib/filters";
import { downloadExport } from "@/lib/download";
import { formatBytes, formatNumber, rangeLabel } from "@/lib/format";
import { cn } from "@/lib/utils";
import type {
  ApplicationSummary,
  Connection,
  DomainSummary,
  EndpointSummary,
  Evidence,
  TimeRange,
} from "@/types";
import type { FlowQuery } from "@/api";

const LIMIT = 50;
const EASE = [0.32, 0.72, 0, 1] as const;

const SCOPES = [
  { value: "flows", label: "Flows" },
  { value: "endpoints", label: "Endpoints" },
  { value: "domains", label: "Domains" },
  { value: "applications", label: "Applications" },
] as const;

type Scope = (typeof SCOPES)[number]["value"];

const NOISE_OPTIONS = [
  { value: "hide", label: "Hide noise" },
  { value: "all", label: "Show all" },
];

/** A table column: every exported column declares its sort field and width. */
type Column = {
  readonly label: string;
  readonly sort: string;
  /** Sort fields a merged column cycles through; defaults to `[sort]`. */
  readonly sorts?: readonly string[];
  readonly width: string;
};

const defaultSort = (scope: Scope) => (scope === "flows" ? "-last_seen" : "-bytes");

const SCOPE_META: Record<
  Scope,
  { title: string; placeholder: string; empty: { title: string; message: string }; unit: string }
> = {
  flows: {
    title: "Flows",
    placeholder: "Search IP, domain, ASN, organization…",
    empty: {
      title: "No matching flows",
      message: "Try clearing the search, removing a filter, or widening the time range.",
    },
    unit: "flows",
  },
  endpoints: {
    title: "Endpoints",
    placeholder: "Search address, organization, ASN…",
    empty: {
      title: "No endpoints yet",
      message: "Remote peers appear here as soon as flows are observed.",
    },
    unit: "endpoints",
  },
  domains: {
    title: "Domains",
    placeholder: "Search domains…",
    empty: {
      title: "No domains observed",
      message:
        "Encrypted traffic without visible DNS or SNI will not appear here. That is expected, not a failure.",
    },
    unit: "domains",
  },
  applications: {
    title: "Applications",
    placeholder: "Search application, executable, container…",
    empty: {
      title: "No applications attributed yet",
      message:
        "Application Identity comes from observed socket ownership. UDP and container traffic under address translation may stay unattributed.",
    },
    unit: "applications",
  },
};

const STATE_OPTIONS = [
  { value: "", label: "All" },
  { value: "active", label: "Active" },
  { value: "ended", label: "Ended" },
];
const VISIBILITY_OPTIONS = [
  { value: "", label: "All" },
  { value: "visible", label: "With domain" },
  { value: "hidden", label: "Without domain" },
];
const TRANSPORT_OPTIONS = [
  { value: "", label: "All" },
  { value: "tcp", label: "TCP" },
  { value: "udp", label: "UDP" },
];
const EVIDENCE_OPTIONS = [
  { value: "any", label: "Any evidence" },
  { value: "dns", label: "DNS" },
  { value: "tls_sni", label: "TLS SNI" },
  { value: "http_host", label: "HTTP Host" },
];
const CONFIDENCE_OPTIONS = [
  { value: "any", label: "Direct + inferred" },
  { value: "direct", label: "Direct" },
  { value: "inferred", label: "Inferred" },
];
const SCOPE_OPTIONS = [
  { value: "any", label: "Any scope" },
  { value: "public", label: "Public" },
  { value: "private", label: "Private" },
  { value: "shared", label: "Carrier NAT" },
  { value: "fake_ip", label: "Fake IP" },
  { value: "loopback", label: "Loopback" },
  { value: "unique_local", label: "Unique local" },
  { value: "link_local", label: "Link-local" },
];

/** Column labels crossfade inside their persistent <th> slot; labels shared
    between scopes ("Traffic", "Last seen") keep their key and never flash. */
function HeadLabel({ label }: { label: string }) {
  const reduceMotion = useReducedMotion();
  return (
    <span className="grid">
      <AnimatePresence mode="popLayout" initial={false}>
        <motion.span
          key={label}
          className="col-start-1 row-start-1 whitespace-nowrap"
          initial={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 7 }}
          animate={reduceMotion ? { opacity: 1 } : { opacity: 1, y: 0 }}
          exit={reduceMotion ? { opacity: 0 } : { opacity: 0, y: -7 }}
          transition={{ duration: 0.2, ease: EASE }}
        >
          {label}
        </motion.span>
      </AnimatePresence>
    </span>
  );
}

/** Compact badge for a merged column's active metric; whole-column metrics are silent. */
const SORT_BADGE: Record<string, string> = {
  bytes: "",
  in_bytes: "down",
  out_bytes: "up",
  rate: "",
  in_rate: "down",
  out_rate: "up",
};

/** Spelled-out metric for tooltips. */
const SORT_TITLE: Record<string, string> = {
  bytes: "total",
  in_bytes: "download",
  out_bytes: "upload",
  rate: "combined rate",
  in_rate: "download rate",
  out_rate: "upload rate",
};

const metricTitle = (field: string) => SORT_TITLE[field] ?? field;

/** Clickable header: toggles ascending/descending, or cycles a metric set. */
function SortableHead({
  column,
  sort,
  onSort,
}: {
  column: Column;
  sort: string;
  onSort: (field: string) => void;
}) {
  const cycle = column.sorts ?? [column.sort];
  const root = sort.replace(/^-/, "");
  const index = cycle.indexOf(root);
  const active = index >= 0;
  const descending = sort.startsWith("-");
  const Icon = active ? (descending ? ArrowDown : ArrowUp) : ArrowUpDown;
  const metric = active && cycle.length > 1 ? SORT_BADGE[cycle[index]] : undefined;
  // Cycle semantics: first click sorts by the headline metric descending, the
  // second flips ascending, the third advances to the next metric.
  const next = () => {
    if (!active) return cycle[0];
    if (descending) return cycle[index];
    return cycle[(index + 1) % cycle.length];
  };
  const title =
    cycle.length > 1
      ? active
        ? `${column.label} sorted by ${metricTitle(cycle[index])} ${descending ? "descending" : "ascending"} — click to ${
            descending
              ? "flip ascending"
              : `sort by ${metricTitle(cycle[(index + 1) % cycle.length])} descending`
          }`
        : `Sort by ${metricTitle(cycle[0])} descending; click again to flip direction or change the metric`
      : `Sort by ${column.label}`;
  return (
    <TableHead>
      <button
        type="button"
        onClick={() => onSort(next())}
        title={title}
        className={cn(
          "group -mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-left transition-colors hover:text-foreground",
          active ? "text-foreground" : "text-muted-foreground",
        )}
      >
        <HeadLabel label={column.label} />
        {metric && <span className="text-2xs font-normal text-muted-foreground">{metric}</span>}
        <Icon
          className={cn(
            "size-3 shrink-0 transition-opacity",
            !active && "opacity-0 group-hover:opacity-50",
          )}
        />
      </button>
    </TableHead>
  );
}

export function ExplorerView() {
  const [searchParams, setSearchParams] = useSearchParams();
  const scopeParam = searchParams.get("scope");
  const scope: Scope =
    scopeParam === "endpoints" || scopeParam === "domains" || scopeParam === "applications"
      ? scopeParam
      : "flows";
  const meta = SCOPE_META[scope];
  const pinned = {
    ip: searchParams.get("ip") ?? "",
    domain: searchParams.get("domain") ?? "",
    country: searchParams.get("country") ?? "",
    asn: searchParams.get("asn") ?? "",
    application: searchParams.get("application") ?? "",
  };

  const [search, setSearch] = useState(searchParams.get("q") ?? "");
  const [appliedQ, setAppliedQ] = useState(searchParams.get("q") ?? "");
  const [range, setRange] = useState<TimeRange>("15m");
  const [customTime, setCustomTime] = useState<TimeWindow | null>(null);
  const [network, setNetwork] = useNetworkFilter();
  const [interfaceName, setInterfaceName] = useInterfaceFilter();
  const [protocol, setProtocol] = useState("");
  const [service, setService] = useState("");
  const [state, setState] = useState("");
  const [visibility, setVisibility] = useState("");
  const [port, setPort] = useState("");
  const [evidence, setEvidence] = useState("");
  const [confidence, setConfidence] = useState("");
  const [scopeFilter, setScopeFilter] = useState(searchParams.get("scope_filter") ?? "");
  const [hideNoise, setHideNoise] = useState(true);
  const [sort, setSort] = useState("-last_seen");
  const [live, setLive] = useState(true);
  const [pendingCount, setPendingCount] = useState(0);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const { open } = useDetails();
  const queryClient = useQueryClient();
  const createExport = useCreateExport();
  const statusQuery = useStatus();
  const serviceOptions = statusQuery.data?.fingerprints.services ?? [];
  const advancedActive =
    Boolean(state || visibility || port || evidence || confidence || scopeFilter) || !hideNoise;
  const reduceMotion = useReducedMotion();

  // Two-phase in-place morph: the tbody element itself never unmounts — the
  // current rows fade out where they stand, the lens swaps while invisible,
  // then the new rows fade back in. The table's height stays locked through
  // the swap and glides to its new size after, so the frame (toolbar, header,
  // pager) never jumps — it reads as one table re-lensed, not a table swap.
  const [displayedScope, setDisplayedScope] = useState<Scope>(scope);
  const [phase, setPhase] = useState<"in" | "out">("in");
  const [lockedHeight, setLockedHeight] = useState<number | null>(null);
  const bodyRef = useRef<HTMLTableSectionElement>(null);

  useEffect(() => {
    if (scope === displayedScope) return;
    if (reduceMotion) {
      setDisplayedScope(scope);
      return;
    }
    const tbody = bodyRef.current;
    if (tbody) setLockedHeight(tbody.getBoundingClientRect().height);
    setPhase("out");
    const timer = window.setTimeout(() => {
      setDisplayedScope(scope);
      setPhase("in");
    }, 130);
    return () => window.clearTimeout(timer);
  }, [scope, displayedScope, reduceMotion]);

  // Switching scope starts a fresh listing; deep links keep their filters.
  const prevScope = useRef(scope);
  useEffect(() => {
    if (prevScope.current === scope) return;
    prevScope.current = scope;
    setSearch("");
    setAppliedQ("");
    setExpandedGroups(new Set());
    setSort(defaultSort(scope));
  }, [scope]);

  // Shared base filters for the Flows lens: connections use them for the
  // merged view and exports reuse them unchanged.
  const timeFilter = customTime
    ? { start: customTime.start, end: customTime.end }
    : { range };
  const scopeFilterParam = scopeFilter || networkScopeParam(network);
  const excludeScopeFilter = scopeFilter ? undefined : excludeScopeParam(network);
  const flowsFilter = useMemo<FlowQuery>(
    () => ({
      q: appliedQ || undefined,
      ...timeFilter,
      state: state || undefined,
      protocol: protocol || undefined,
      interface: interfaceName || undefined,
      service: service || undefined,
      port: port ? Number(port) : undefined,
      evidence: (evidence || undefined) as Evidence | undefined,
      confidence: confidence || undefined,
      scope: scopeFilterParam,
      exclude_scope: excludeScopeFilter,
      has_domain: visibility === "visible" ? true : visibility === "hidden" ? false : undefined,
      ip: pinned.ip || undefined,
      domain: pinned.domain || undefined,
      application_id: pinned.application || undefined,
      country: pinned.country || undefined,
      asn: pinned.asn ? Number(pinned.asn) : undefined,
      sort: scope === "flows" ? sort : "-last_seen",
      limit: LIMIT,
    }),
    [appliedQ, range, customTime, state, visibility, protocol, service, port, evidence, confidence, scopeFilterParam, excludeScopeFilter, sort, scope, interfaceName, pinned.ip, pinned.domain, pinned.application, pinned.country, pinned.asn],
  );
  const connectionsFilter = useMemo<FlowQuery>(
    () => ({ ...flowsFilter, hide_noise: hideNoise }),
    [flowsFilter, hideNoise],
  );
  const connectionsQuery = useConnectionsInfinite(connectionsFilter);
  const endpointsQuery = useEndpointsInfinite({
    q: appliedQ || undefined,
    ...timeFilter,
    protocol: protocol || undefined,
    service: service || undefined,
    interface: interfaceName || undefined,
    scope: networkScopeParam(network),
    exclude_scope: excludeScopeParam(network),
    sort: scope === "endpoints" ? sort : "-bytes",
    limit: LIMIT,
  });
  const domainsQuery = useDomainsInfinite({
    q: appliedQ || undefined,
    ...timeFilter,
    interface: interfaceName || undefined,
    scope: networkScopeParam(network),
    exclude_scope: excludeScopeParam(network),
    sort: scope === "domains" ? sort : "-bytes",
    limit: LIMIT,
  });
  const applicationsQuery = useApplicationsInfinite({
    q: appliedQ || undefined,
    ...timeFilter,
    interface: interfaceName || undefined,
    scope: networkScopeParam(network),
    exclude_scope: excludeScopeParam(network),
    sort: scope === "applications" ? sort : "-bytes",
    limit: LIMIT,
  });

  const activeQuery =
    scope === "endpoints"
      ? endpointsQuery
      : scope === "domains"
        ? domainsQuery
        : scope === "applications"
          ? applicationsQuery
          : connectionsQuery;
  const total = activeQuery.data?.pages[0]?.total ?? 0;
  const searchRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const onFocus = () => searchRef.current?.focus();
    window.addEventListener(FOCUS_SEARCH_EVENT, onFocus);
    return () => window.removeEventListener(FOCUS_SEARCH_EVENT, onFocus);
  }, []);

  // Compact search field rendered in the topbar's trailing slot; the node is
  // memoized so the topbar only re-renders when the field actually changes.
  const searchField = useMemo(
    () => (
      <label className="relative block">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input
          ref={searchRef}
          type="search"
          value={search}
          onChange={(event) => {
            setLiveAndSync(false);
            setSearch(event.target.value);
          }}
          onFocus={() => setLiveAndSync(false)}
          placeholder={meta.placeholder}
          autoComplete="off"
          spellCheck={false}
          className="h-8 w-36 pl-8 text-xs md:text-xs sm:w-64"
        />
      </label>
    ),
    [search, meta.placeholder],
  );

  useSetTopbar(
    meta.title,
    scope === "flows"
      ? pinned.ip && total
        ? `${formatNumber(total)} connections · endpoint ${pinned.ip}`
        : pinned.domain && total
          ? `${formatNumber(total)} connections · ${pinned.domain}`
          : `${formatNumber(total)} connections in last ${rangeLabel(range)}`
      : scope === "endpoints"
        ? `${formatNumber(total)} remote peers`
        : scope === "domains"
          ? `${formatNumber(total)} associated domains`
          : `${formatNumber(total)} applications`,
    searchField,
  );

  const [endpointItems, setEndpointItems] = useState<EndpointSummary[]>([]);
  useEffect(() => {
    if (endpointsQuery.data) setEndpointItems(endpointsQuery.data.pages.flatMap((page) => page.items));
  }, [endpointsQuery.data]);

  const [domainItems, setDomainItems] = useState<DomainSummary[]>([]);
  useEffect(() => {
    if (domainsQuery.data) setDomainItems(domainsQuery.data.pages.flatMap((page) => page.items));
  }, [domainsQuery.data]);

  const [applicationItems, setApplicationItems] = useState<ApplicationSummary[]>([]);
  useEffect(() => {
    if (applicationsQuery.data) {
      setApplicationItems(applicationsQuery.data.pages.flatMap((page) => page.items));
    }
  }, [applicationsQuery.data]);

  const [connectionItems, setConnectionItems] = useState<Connection[]>([]);
  useEffect(() => {
    if (connectionsQuery.data) {
      setConnectionItems(connectionsQuery.data.pages.flatMap((page) => page.items));
    }
  }, [connectionsQuery.data]);

  const loadedCount =
    scope === "endpoints"
      ? endpointItems.length
      : scope === "domains"
        ? domainItems.length
        : scope === "applications"
          ? applicationItems.length
          : connectionItems.length;

  // Connections fold into group headers; expanding a group adds child rows.
  const connectionGroups = useMemo(
    () => (displayedScope === "flows" ? groupConnections(connectionItems, sort) : []),
    [displayedScope, connectionItems, sort],
  );
  const flatConnections = useMemo(
    () => flattenConnectionGroups(connectionGroups, expandedGroups),
    [connectionGroups, expandedGroups],
  );
  // The live stream is retargeted to the same filters the connection list
  // uses, so ticks only carry rows this view can show.
  useEffect(() => {
    setStreamQuery({
      q: appliedQ || undefined,
      state: state || undefined,
      protocol: protocol || undefined,
      port: port ? Number(port) : undefined,
      scope: networkScopeParam(network),
      exclude_scope: excludeScopeParam(network),
      has_domain: visibility === "visible" ? true : visibility === "hidden" ? false : undefined,
      ip: pinned.ip || undefined,
      domain: pinned.domain || undefined,
      application_id: pinned.application || undefined,
    });
  }, [appliedQ, state, visibility, protocol, port, network, pinned.ip, pinned.domain, pinned.application]);

  // Clear the stream filters only when leaving the view, not between filter
  // updates (a per-update reset caused an extra reconnect on every change).
  useEffect(() => () => setStreamQuery({}), []);

  // Live tick handling: aggregate rows patch in place, and every sixth tick
  // the visible list refreshes so new rows surface — but only while the
  // first page is all that is loaded, so scrolled-down pages stay put.
  const liveRef = useRef(live);
  liveRef.current = live;
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const pagesLoadedRef = useRef(1);
  pagesLoadedRef.current = activeQuery.data?.pages.length ?? 1;
  const connectionItemsRef = useRef(connectionItems);
  connectionItemsRef.current = connectionItems;
  const tickCount = useRef(0);

  useEffect(
    () =>
      subscribeTicks((tick) => {
        // Endpoint and Domain aggregates ride every tick: patch known rows in
        // place, let the periodic refresh surface newly ranked rows.
        if (tick.endpoints.length) {
          const updates = new Map(tick.endpoints.map((endpoint) => [endpoint.address, endpoint]));
          startTransition(() => {
            setEndpointItems((previous) => {
              let changed = false;
              const next = previous.map((endpoint) => {
                const update = updates.get(endpoint.address);
                if (!update) return endpoint;
                changed = true;
                return update;
              });
              return changed ? next : previous;
            });
          });
        }
        if (tick.domains.length) {
          const updates = new Map(tick.domains.map((domain) => [domain.domain, domain]));
          startTransition(() => {
            setDomainItems((previous) => {
              let changed = false;
              const next = previous.map((domain) => {
                const update = updates.get(domain.domain);
                if (!update) return domain;
                changed = true;
                return update;
              });
              return changed ? next : previous;
            });
          });
        }
        if (tick.applications.length) {
          const updates = new Map(
            tick.applications.map((application) => [application.id, application]),
          );
          startTransition(() => {
            setApplicationItems((previous) => {
              let changed = false;
              const next = previous.map((application) => {
                const update = updates.get(application.id);
                if (!update) return application;
                changed = true;
                return update;
              });
              return changed ? next : previous;
            });
          });
        }

        tickCount.current += 1;
        if (tickCount.current % 6 === 0 && pagesLoadedRef.current === 1) {
          if (scopeRef.current === "endpoints") {
            void queryClient.invalidateQueries({ queryKey: ["endpoints-page"] });
          } else if (scopeRef.current === "domains") {
            void queryClient.invalidateQueries({ queryKey: ["domains-page"] });
          } else if (scopeRef.current === "applications") {
            void queryClient.invalidateQueries({ queryKey: ["applications-page"] });
          } else if (liveRef.current) {
            void queryClient.invalidateQueries({ queryKey: ["connections-page"] });
          }
        }

        if (scopeRef.current !== "flows") return;

        // Connections cannot be patched from directional ticks; pause just
        // counts how many visible peers saw activity.
        if (!liveRef.current) {
          const peers = new Set(
            connectionItemsRef.current.map((connection) => connection.remote.address),
          );
          const updates = [
            ...tick.flows.map((flow) => flow.remote.address),
            ...tick.flow_updates.map((patch) => patch.remote),
          ].filter((address) => peers.has(address));
          if (updates.length) setPendingCount((count) => count + updates.length);
        }
      }),
    [queryClient],
  );

  // Infinite scroll: a sentinel below the table loads the next page as it
  // enters the viewport, so the list just keeps going instead of paging. A
  // post-render check resumes loading when the sentinel stays visible after
  // a page arrives (IntersectionObserver would not fire again).
  const loadMoreRef = useRef<HTMLDivElement>(null);
  const sentinelVisible = useRef(false);
  const loadMoreState = useRef({
    hasNextPage: false,
    isFetchingNextPage: false,
    isPlaceholderData: false,
    fetchNextPage: () => {},
  });
  loadMoreState.current = {
    hasNextPage: Boolean(activeQuery.hasNextPage),
    isFetchingNextPage: activeQuery.isFetchingNextPage,
    isPlaceholderData: activeQuery.isPlaceholderData,
    fetchNextPage: activeQuery.fetchNextPage,
  };
  const maybeLoadMore = () => {
    const state = loadMoreState.current;
    if (sentinelVisible.current && state.hasNextPage && !state.isFetchingNextPage && !state.isPlaceholderData) {
      void state.fetchNextPage();
    }
  };
  useEffect(() => {
    const node = loadMoreRef.current;
    if (!node) return;
    const observer = new IntersectionObserver(
      (entries) => {
        sentinelVisible.current = entries.some((entry) => entry.isIntersecting);
        maybeLoadMore();
      },
      { rootMargin: "600px 0px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  useEffect(maybeLoadMore);

  const setLiveAndSync = (next: boolean) => {
    setLive(next);
    if (next) {
      setPendingCount(0);
      void queryClient.invalidateQueries({ queryKey: ["connections-page"] });
    }
  };

  // Debounced search: typing or focusing the field pauses live updates first.
  useEffect(() => {
    if (search === appliedQ) return;
    const timer = window.setTimeout(() => {
      setAppliedQ(search.trim());
    }, 220);
    return () => window.clearTimeout(timer);
  }, [search, appliedQ]);

  // Deep links: ?flow=…, ?address=… and ?domain=… (per scope) open detail.
  const detailParam =
    scope === "flows"
      ? searchParams.get("flow")
      : scope === "endpoints"
        ? searchParams.get("address")
        : scope === "domains"
          ? searchParams.get("domain")
          : searchParams.get("application");
  const openedDeepLink = useRef(false);
  useEffect(() => {
    if (!detailParam || !activeQuery.isSuccess || openedDeepLink.current) return;
    openedDeepLink.current = true;
    if (scope === "flows") open({ kind: "flow", id: detailParam });
    else if (scope === "endpoints") open({ kind: "endpoint", address: detailParam });
    else if (scope === "domains") open({ kind: "domain", name: detailParam });
    else open({ kind: "application", id: detailParam });
  }, [detailParam, scope, activeQuery.isSuccess, open]);

  const unpin = (key: keyof typeof pinned) => {
    const next = new URLSearchParams(searchParams);
    next.delete(key);
    setSearchParams(next, { replace: true });
  };

  const runExport = (format: "json" | "csv") =>
    createExport.mutate(
      { ...flowsFilter, format },
      {
        onSuccess: (task) => {
          toast.success(
            `Export ready · ${formatNumber(task.record_count)} records · ${formatBytes(task.size_bytes)}`,
            {
              description: task.truncated ? "Only the first 10,000 records are included." : undefined,
              action: { label: "Download", onClick: () => downloadExport(task.id) },
            },
          );
        },
      },
    );

  // One route, one table: the scope control only rewrites `?scope=`.
  const switchScope = (value: string) => {
    if (value === scope) return;
    const next = new URLSearchParams();
    next.set("scope", value);
    setSearchParams(next, { replace: true });
  };

  const toggleSort = (field: string) => {
    const current = sort.startsWith("-") ? sort.slice(1) : sort;
    setSort(current === field ? (sort.startsWith("-") ? field : `-${field}`) : `-${field}`);
  };

  const columns: readonly Column[] =
    scope === "flows"
      ? CONNECTION_COLUMNS
      : scope === "endpoints"
        ? ENDPOINT_COLUMNS
        : scope === "domains"
          ? DOMAIN_COLUMNS
          : APPLICATION_COLUMNS;
  const pinnedChips = (Object.entries(pinned) as Array<[keyof typeof pinned, string]>).filter(([, value]) => value);

  const renderRows = (active: Scope) => {
    if (active === "flows") {
      return (
        <ConnectionRows
          items={flatConnections}
          onToggle={(key) =>
            setExpandedGroups((previous) => {
              const next = new Set(previous);
              if (next.has(key)) next.delete(key);
              else next.add(key);
              return next;
            })
          }
          onOpen={(address) => open({ kind: "endpoint", address })}
        />
      );
    }
    if (active === "endpoints") {
      return endpointItems.map((endpoint) => (
        <EndpointRow
          key={endpoint.address}
          endpoint={endpoint}
          onOpen={(address) => open({ kind: "endpoint", address })}
        />
      ));
    }
    if (active === "applications") {
      return applicationItems.map((application) => (
        <ApplicationRow
          key={application.id}
          application={application}
          onOpen={(id) => open({ kind: "application", id })}
        />
      ));
    }
    return domainItems.map((domain) => (
      <DomainRow
        key={domain.domain}
        domain={domain}
        onOpen={(name) => open({ kind: "domain", name })}
      />
    ));
  };

  // Body content follows the *displayed* lens so rows fade in place — only
  // the content swaps mid-fade, never the table frame.
  const displayedColumns =
    displayedScope === "flows"
      ? CONNECTION_COLUMNS
      : displayedScope === "endpoints"
        ? ENDPOINT_COLUMNS
        : displayedScope === "domains"
          ? DOMAIN_COLUMNS
          : APPLICATION_COLUMNS;
  const bodyQuery =
    displayedScope === "flows"
      ? connectionsQuery
      : displayedScope === "endpoints"
        ? endpointsQuery
        : displayedScope === "domains"
          ? domainsQuery
          : applicationsQuery;
  const bodyRows = renderRows(displayedScope);
  const bodyEmpty =
    displayedScope === "flows"
      ? connectionItems.length === 0
      : displayedScope === "endpoints"
        ? endpointItems.length === 0
        : displayedScope === "domains"
          ? domainItems.length === 0
          : applicationItems.length === 0;
  const emptyCopy = bodyQuery.isError
    ? {
        title: "Agent unavailable",
        message:
          bodyQuery.error instanceof Error
            ? bodyQuery.error.message
            : "The local agent did not respond. Check that it is running.",
      }
    : displayedScope === "flows"
      ? {
          title: "No matching connections",
          message: "Try widening the time range, showing noise, or clearing filters.",
        }
      : SCOPE_META[displayedScope].empty;
  const bodyContent = bodyQuery.isLoading ? (
    <TableSkeleton rows={8} columns={displayedColumns.length} />
  ) : !bodyEmpty ? (
    bodyRows
  ) : (
    <TableRow className="hover:bg-transparent">
      <TableCell colSpan={displayedColumns.length}>
        <EmptyState icon={Search} title={emptyCopy.title} message={emptyCopy.message} />
      </TableCell>
    </TableRow>
  );

  return (
    <section className="flex flex-col">
      <div className="flex flex-col gap-2.5 pb-3">
        <div className="flex flex-wrap items-center gap-2">
          <Segmented ariaLabel="Data scope" options={[...SCOPES]} value={scope} onChange={switchScope} />
          <div className="flex-1" />
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={scope}
              className="flex items-center gap-2"
              initial={reduceMotion ? { opacity: 0 } : { opacity: 0, y: -4 }}
              animate={reduceMotion ? { opacity: 1 } : { opacity: 1, y: 0 }}
              exit={reduceMotion ? { opacity: 0 } : { opacity: 0, y: 4 }}
              transition={{ duration: 0.16, ease: EASE }}
            >
              {scope === "flows" ? (
                <>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="secondary" size="sm">
                        <Download className="size-3.5" />
                        Export
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-56">
                      <DropdownMenuItem onSelect={() => void runExport("json")}>JSON summary</DropdownMenuItem>
                      <DropdownMenuItem onSelect={() => void runExport("csv")}>CSV records</DropdownMenuItem>
                      <p className="border-t px-2 py-2 text-2xs leading-relaxed text-muted-foreground">
                        Exports contain Flow metadata, evidence and IP profiles — never payloads.
                      </p>
                    </DropdownMenuContent>
                  </DropdownMenu>
                  <Button
                    variant={live ? "secondary" : "outline"}
                    size="sm"
                    onClick={() => setLiveAndSync(!live)}
                    aria-pressed={live}
                  >
                    <i
                      className={cn(
                        "size-1.5 rounded-full",
                        live ? "bg-success" : pendingCount ? "bg-warning" : "bg-muted-foreground/40",
                      )}
                    />
                    {live ? "Live" : pendingCount ? `Paused · ${pendingCount} updates` : "Paused"}
                  </Button>
                </>
              ) : scope === "endpoints" ? (
                <span className="inline-flex items-center gap-1.5 text-2xs text-muted-foreground">
                  <Info className="size-3.5" />
                  Public addresses enriched locally
                </span>
              ) : scope === "domains" ? (
                <span className="inline-flex items-center gap-1.5 text-2xs text-muted-foreground">
                  <Lock className="size-3.5" />
                  Domains stay on this device
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-2xs text-muted-foreground">
                  <Info className="size-3.5" />
                  From observed socket ownership; unattributed traffic stays visible in Flows
                </span>
              )}
            </motion.div>
          </AnimatePresence>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <TimeFilter
            range={range}
            custom={customTime}
            onRange={setRange}
            onCustom={setCustomTime}
          />
          <NetworkFilterControl value={network} onChange={setNetwork} />
          <InterfaceFilterControl value={interfaceName} onChange={setInterfaceName} />
          {(scope === "flows" || scope === "endpoints") && (
            <Segmented
              ariaLabel="Transport protocol"
              options={TRANSPORT_OPTIONS}
              value={protocol}
              onChange={setProtocol}
            />
          )}
          {(scope === "flows" || scope === "endpoints") && (
            <Select value={service || "any"} onValueChange={(value) => setService(value === "any" ? "" : value)}>
              <SelectTrigger aria-label="Service" size="sm" className="w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">Any service</SelectItem>
                {serviceOptions.map((name) => (
                  <SelectItem key={name} value={name}>
                    {name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
          <div className="flex-1" />
          {scope === "flows" && (
            <Popover>
              <PopoverTrigger asChild>
                <Button variant="outline" size="sm">
                  <SlidersHorizontal className="size-3.5" />
                  More filters
                  {advancedActive && <i className="size-1.5 rounded-full bg-primary" />}
                </Button>
              </PopoverTrigger>
              <PopoverContent align="end" className="w-80">
                <div className="grid gap-3">
                  <div className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">Flow state</span>
                    <Segmented
                      ariaLabel="Flow state"
                      options={STATE_OPTIONS}
                      value={state}
                      onChange={setState}
                    />
                  </div>
                  <div className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">Associated domain</span>
                    <Segmented
                      ariaLabel="Domain visibility"
                      options={VISIBILITY_OPTIONS}
                      value={visibility}
                      onChange={setVisibility}
                    />
                  </div>
                  <div className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">
                      DNS and sub-second chatter
                    </span>
                    <Segmented
                      ariaLabel="Noise"
                      options={NOISE_OPTIONS}
                      value={hideNoise ? "hide" : "all"}
                      onChange={(value) => setHideNoise(value === "hide")}
                    />
                  </div>
                  <label className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">Port</span>
                    <Input
                      inputMode="numeric"
                      value={port}
                      placeholder="any"
                      aria-label="Port"
                      onChange={(event) => {
                        setPort(event.target.value.replace(/[^0-9]/g, ""));
                      }}
                      className="h-8 w-24 text-xs"
                    />
                  </label>
                  <label className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">Domain evidence</span>
                    <Select value={evidence || "any"} onValueChange={(value) => setEvidence(value === "any" ? "" : value)}>
                      <SelectTrigger aria-label="Domain evidence" size="sm">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {EVIDENCE_OPTIONS.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </label>
                  <label className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">Association</span>
                    <Select value={confidence || "any"} onValueChange={(value) => setConfidence(value === "any" ? "" : value)}>
                      <SelectTrigger aria-label="Association confidence" size="sm">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {CONFIDENCE_OPTIONS.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </label>
                  <label className="grid gap-1">
                    <span className="text-2xs font-medium text-muted-foreground">Address scope</span>
                    <Select value={scopeFilter || "any"} onValueChange={(value) => setScopeFilter(value === "any" ? "" : value)}>
                      <SelectTrigger aria-label="Address scope" size="sm">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SCOPE_OPTIONS.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </label>
                </div>
              </PopoverContent>
            </Popover>
          )}
        </div>
        {scope === "flows" && pinnedChips.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {pinnedChips.map(([key, value]) => (
              <button
                key={key}
                type="button"
                onClick={() => unpin(key)}
                className="inline-flex max-w-72 items-center gap-1 rounded-full border border-border/70 bg-secondary px-2 py-0.5 text-xs text-muted-foreground hover:bg-accent"
              >
                {key.toUpperCase()}
                <strong className="truncate font-mono text-[17px] font-medium text-foreground">{value}</strong>
                <X className="size-3" />
                <span className="sr-only">Remove filter</span>
              </button>
            ))}
          </div>
        )}
      </div>

      <RowContextMenu>
        <motion.div
          className="layered-surface overflow-hidden rounded-xl"
          style={{ viewTransitionName: "flows-surface" }}
          initial={false}
          animate={{ height: lockedHeight ?? "auto" }}
          transition={{ duration: 0.28, ease: EASE }}
        >
          <Table className="table-fixed">
            <colgroup>
              {columns.map((column) => (
                <col key={column.label} style={{ width: column.width }} />
              ))}
            </colgroup>
            <TableHeader>
              <TableRow>
                {columns.map((column) => (
                  <SortableHead key={column.label} column={column} sort={sort} onSort={toggleSort} />
                ))}
              </TableRow>
            </TableHeader>
            <motion.tbody
              ref={bodyRef}
              data-slot="table-body"
              className="explorer-table-body [&_tr:last-child]:border-0"
              initial={false}
              animate={phase === "out" ? { opacity: 0, y: -4 } : { opacity: 1, y: 0 }}
              transition={{ duration: phase === "out" ? 0.13 : 0.2, ease: EASE }}
              onAnimationComplete={() => {
                if (phase === "in") setLockedHeight(null);
              }}
            >
              {bodyContent}
            </motion.tbody>
          </Table>
        </motion.div>
      </RowContextMenu>

      <div ref={loadMoreRef} aria-hidden className="h-px" />
      <div className="flex items-center justify-between gap-3 py-2.5 text-2xs text-muted-foreground">
        <span className="tabular-nums">
          {formatNumber(loadedCount)} of {formatNumber(total)}{" "}
          {scope === "flows" ? "connections" : meta.unit}
        </span>
        <span className="inline-flex items-center gap-1.5">
          {activeQuery.isFetchingNextPage ? (
            <>
              <Loader2 className="size-3 animate-spin" />
              Loading more…
            </>
          ) : activeQuery.hasNextPage ? (
            "Scroll for more"
          ) : total > 0 ? (
            "All loaded"
          ) : null}
        </span>
      </div>
    </section>
  );
}
