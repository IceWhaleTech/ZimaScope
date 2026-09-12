/**
 * Overview — "what is happening right now, where is it going, is collection
 * healthy?" Rates first, then the timeline, then ranked destinations. The
 * page is deliberately flat: no boxed cards, sections separated by
 * whitespace and hairlines, so wide screens fill with content instead of
 * empty card padding. Live ticks ease the rate numbers and patch the
 * recent-flows rows in place.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { motion, useReducedMotion } from "motion/react";
import { ArrowLeftRight, ChevronDown, ChevronRight, Info, TriangleAlert } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TimelineChart, rateSeries, Sparkline } from "@/components/charts";
import { FlowRow, FLOW_COLUMNS } from "@/components/flow-table";
import { RankList } from "@/components/rank-list";
import { Segmented } from "@/components/segmented";
import { SpringNumber } from "@/components/spring-number";
import { useDetails } from "@/hooks/use-details";
import { queryKeys, useFlows, useOverview, useStatus } from "@/hooks/use-data";
import { useHideLan } from "@/hooks/use-hide-lan";
import { useSetTopbar } from "@/hooks/use-topbar";
import { useTick } from "@/hooks/use-tick";
import { data } from "@/store";
import { excludeScopeParam } from "@/lib/filters";
import { markSurfaceMorph, runViewTransition } from "@/lib/view-morph";
import { evidenceLabel, flagEmoji, formatBytes, formatNumber, formatPercent, formatRate, networkLabel, rangeLabel, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FlowQuery } from "@/api";
import type {
  CollectorHealth,
  Flow,
  ServiceStatus,
  TimeRange,
} from "@/types";

const RANGES = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

const LAN_OPTIONS = [
  { value: "all", label: "All traffic" },
  { value: "internet", label: "Internet only" },
];

export function OverviewView() {
  const [range, setRange] = useState<TimeRange>("15m");
  const [hideLan, setHideLan] = useHideLan();
  const excludeScope = excludeScopeParam(hideLan);
  const overviewQuery = useOverview(range, excludeScope);
  const overview = overviewQuery.data;
  const flowsQuery = useFlows({ sort: "-last_seen", limit: 200, exclude_scope: excludeScope });
  const statusQuery = useStatus();
  const tick = useTick();
  const queryClient = useQueryClient();
  const { open, target } = useDetails();
  const navigate = useNavigate();
  const reduceMotion = useReducedMotion();
  useSetTopbar("Overview", `Last ${rangeLabel(range)}`);

  // One scroll past the Recent flows ledger hands the same table over to the
  // Explorer: the payload is prefetched first so the morph lands on real rows,
  // and the surface is morphed by the View Transitions API.
  const scrollTriggerRef = useRef<HTMLDivElement>(null);
  const morphStarted = useRef(false);
  const hoveringRows = useRef(false);
  const detailsOpen = useRef(false);
  detailsOpen.current = target !== null;

  const explorerDefaults = useMemo<FlowQuery>(
    () => ({
      range: "15m",
      exclude_scope: excludeScopeParam(hideLan),
      sort: "-last_seen",
      limit: 50,
      hide_noise: true,
    }),
    [hideLan],
  );

  const openFlows = useCallback(async () => {
    try {
      // The Explorer consumes this key as an infinite query; prefetch it with
      // the same shape and pagination contract so the morph lands on rows.
      await queryClient.ensureInfiniteQueryData({
        queryKey: queryKeys.connectionsPage(explorerDefaults),
        queryFn: ({ pageParam }) => data.connections({ ...explorerDefaults, offset: pageParam }),
        initialPageParam: 0,
        getNextPageParam: (last: { items: unknown[]; total: number; offset: number }) => {
          const next = last.offset + last.items.length;
          return last.items.length > 0 && next < last.total ? next : undefined;
        },
      });
    } catch {
      // Fall through: the Explorer shows its own unavailable state.
    }
    runViewTransition(() => {
      markSurfaceMorph();
      // The Explorer's Flows lens shows merged Connections, the same traffic
      // grouped into the endpoint pairs the Recent flows rows belong to.
      navigate("/explore?scope=flows");
    });
  }, [queryClient, explorerDefaults, navigate]);

  useEffect(() => {
    const trigger = scrollTriggerRef.current;
    if (!trigger) return;
    let timer: number | undefined;
    const cancel = () => {
      if (timer !== undefined) {
        window.clearTimeout(timer);
        timer = undefined;
      }
    };
    // Arm only when the ledger is visible and the page is at its end; the
    // brief dwell keeps a quick flick from stealing a click on a row.
    const arm = () => {
      if (morphStarted.current || detailsOpen.current || hoveringRows.current) {
        cancel();
        return;
      }
      const atEnd =
        window.innerHeight + window.scrollY >=
        document.documentElement.scrollHeight - 24;
      const visible = trigger.getBoundingClientRect().top < window.innerHeight;
      if (!atEnd || !visible) {
        cancel();
        return;
      }
      if (timer !== undefined) return;
      timer = window.setTimeout(() => {
        timer = undefined;
        if (morphStarted.current || detailsOpen.current || hoveringRows.current) {
          return;
        }
        morphStarted.current = true;
        void openFlows();
      }, 320);
    };
    window.addEventListener("scroll", arm, { passive: true });
    window.addEventListener("resize", arm);
    arm();
    return () => {
      cancel();
      window.removeEventListener("scroll", arm);
      window.removeEventListener("resize", arm);
    };
  }, [openFlows]);

  const [recent, setRecent] = useState<Flow[]>([]);
  useEffect(() => {
    if (flowsQuery.data) setRecent(flowsQuery.data.items.slice(0, 8));
  }, [flowsQuery.data]);

  // Live counters: authoritative from the tick. The tick also drives a
  // periodic REST refresh for the ranked lists, which are range-scoped and
  // cannot be patched from the all-history tick aggregates.
  const activeFlows = tick?.overview.active_flows ?? overview?.active_flows ?? 0;
  const overviewTicks = useRef(0);

  const rateHistory = useRef<{ inbound: number[]; outbound: number[] }>({ inbound: [], outbound: [] });
  useEffect(() => {
    if (overview) rateHistory.current = rateSeries(overview.timeline.points);
  }, [overview]);

  useEffect(() => {
    if (!tick) return;
    rateHistory.current.inbound.push(tick.traffic.inbound_bps);
    rateHistory.current.outbound.push(tick.traffic.outbound_bps);
    if (rateHistory.current.inbound.length > 60) {
      rateHistory.current.inbound.shift();
      rateHistory.current.outbound.shift();
    }
    const byId = new Map(tick.flows.map((flow) => [flow.id, flow]));
    setRecent((previous) => previous.map((flow) => byId.get(flow.id) ?? flow));

    overviewTicks.current += 1;
    if (overviewTicks.current % 6 === 0) {
      void queryClient.invalidateQueries({ queryKey: queryKeys.overview(range, excludeScope) });
    }
  }, [tick, range, excludeScope, queryClient]);

  const timelinePoints = useMemo(() => {
    if (!overview) return [];
    const points = overview.timeline.points;
    if (!tick || points.length === 0) return points;
    const next = points.slice();
    const last = { ...next[next.length - 1] };
    last.inbound = {
      bytes: last.inbound.bytes + tick.traffic.inbound.bytes,
      packets: last.inbound.packets + tick.traffic.inbound.packets,
    };
    last.outbound = {
      bytes: last.outbound.bytes + tick.traffic.outbound.bytes,
      packets: last.outbound.packets + tick.traffic.outbound.packets,
    };
    next[next.length - 1] = last;
    return next;
  }, [overview, tick]);

  const rates = tick?.traffic
    ? { inbound_bps: tick.traffic.inbound_bps, outbound_bps: tick.traffic.outbound_bps }
    : overview?.rates;

  return (
    <div className="flex flex-col gap-10">
      <CollectionNotice
        status={statusQuery.data}
        health={overview?.health ?? tick?.health ?? null}
        error={overviewQuery.isError ? errorText(overviewQuery.error) : undefined}
      />

      <section className="grid gap-x-12 gap-y-8 lg:grid-cols-2">
        <RateCard
          direction="inbound"
          title="Inbound"
          subtitle="Entering ZimaOS"
          bps={rates?.inbound_bps ?? 0}
          total={overview ? formatBytes(overview.totals.inbound.bytes) : "—"}
          packets={overview ? `${formatNumber(overview.totals.inbound.packets)} packets` : "—"}
          spark={rateHistory.current.inbound}
        />
        <RateCard
          direction="outbound"
          title="Outbound"
          subtitle="Leaving ZimaOS"
          bps={rates?.outbound_bps ?? 0}
          total={overview ? formatBytes(overview.totals.outbound.bytes) : "—"}
          packets={overview ? `${formatNumber(overview.totals.outbound.packets)} packets` : "—"}
          spark={rateHistory.current.outbound}
          className="lg:pl-12"
        />
      </section>

      <section className="layered-surface grid grid-cols-2 gap-x-12 gap-y-6 rounded-xl px-5 py-5 xl:grid-cols-4">
        {!overview ? (
          Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-14" />)
        ) : (
          <StatCards overview={overview} activeFlows={activeFlows} />
        )}
      </section>

      <section className="flex flex-col gap-4">
        <SectionHead
          title="Traffic timeline"
          description="Bytes observed per interval at the device boundary"
          action={
            <span className="flex flex-wrap items-center gap-2">
              <Segmented
                ariaLabel="Local traffic"
                options={LAN_OPTIONS}
                value={hideLan ? "internet" : "all"}
                onChange={(value) => setHideLan(value === "internet")}
              />
              <Segmented ariaLabel="Time range" options={RANGES} value={range} onChange={(value) => setRange(value as TimeRange)} />
            </span>
          }
        />
        <TimelineChart points={timelinePoints} />
        <div className="flex items-center gap-4 text-2xs text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <i className="size-1.5 rounded-full bg-series-inbound" />Inbound
          </span>
          <span className="inline-flex items-center gap-1.5">
            <i className="size-1.5 rounded-full bg-series-outbound" />Outbound
          </span>
          <span className="ml-auto inline-flex items-center gap-1">
            <Info className="size-3" />
            Hover for interval detail
          </span>
        </div>
      </section>

      <section className="grid gap-x-12 gap-y-8 md:grid-cols-2 xl:grid-cols-4">
        <RankSection title="Top domains" subtitle="By bytes, current range">
          {!overview ? (
            <SkeletonRows count={5} />
          ) : (
            <RankList
              emptyText="No domain evidence observed yet"
              items={overview.top_domains.map((item) => ({
                label: item.domain,
                sub: `${item.flow_count} flows · ${item.evidence.map((evidence) => evidenceLabel(evidence)).join(" · ")}`,
                value: formatBytes(item.bytes),
                ratio: item.bytes / Math.max(1, ...overview.top_domains.map((entry) => entry.bytes)),
                href: `/explore?scope=flows&domain=${encodeURIComponent(item.domain)}`,
              }))}
            />
          )}
        </RankSection>

        <RankSection title="Top endpoints" subtitle="Remote peers by bytes">
          {!overview ? (
            <SkeletonRows count={5} />
          ) : (
            <RankList
              emptyText="No remote endpoints in range"
              items={overview.top_endpoints.map((item) => ({
                label: item.address,
                sub: `${item.flow_count} flows · ${networkLabel(item.scope, item.organization)}`,
                value: formatBytes(item.bytes),
                ratio: item.bytes / Math.max(1, ...overview.top_endpoints.map((entry) => entry.bytes)),
                href: `/explore?scope=flows&ip=${encodeURIComponent(item.address)}`,
              }))}
            />
          )}
        </RankSection>

        <RankSection title="Regions" subtitle="Where traffic exits the Device Boundary">
          {!overview ? (
            <SkeletonRows count={5} />
          ) : (
            <>
              <RankList
                emptyText="No public endpoints in range"
                items={overview.top_countries.map((item) => ({
                  label: item.country,
                  leading: <span aria-hidden>{flagEmoji(item.country)}</span>,
                  sub: `${item.flows} flows`,
                  value: formatBytes(item.bytes),
                  ratio: item.bytes / Math.max(1, ...overview.top_countries.map((entry) => entry.bytes)),
                  href: `/explore?scope=flows&country=${encodeURIComponent(item.country)}`,
                }))}
              />
              {overview.proxied.flows > 0 && (
                <p className="mt-2 text-2xs leading-relaxed text-muted-foreground">
                  {formatBytes(overview.proxied.bytes)} across {formatNumber(overview.proxied.flows)} flows
                  went through the local proxy (fake IP).{" "}
                  {overview.proxied.resolved_flows === 0
                    ? "Their real destinations never cross this boundary; connect the proxy control API in Settings to resolve them."
                    : overview.proxied.resolved_flows < overview.proxied.flows
                      ? `${formatNumber(overview.proxied.resolved_flows)} resolved through the proxy control API (regions show the proxy egress node), ${formatNumber(
                          overview.proxied.flows - overview.proxied.resolved_flows,
                        )} still unknown.`
                      : "Destinations resolved through the proxy control API; regions show the proxy egress node."}{" "}
                  <Link
                    to="/explore?scope=flows&scope_filter=fake_ip"
                    className="font-medium text-primary hover:underline"
                  >
                    View proxied flows
                  </Link>
                </p>
              )}
            </>
          )}
        </RankSection>

        <RankSection title="Networks" subtitle="ASN and organization">
          {!overview ? (
            <SkeletonRows count={5} />
          ) : (
            <RankList
              emptyText="No ASN data available"
              items={overview.top_asns.map((item) => ({
                label: `AS${item.asn}`,
                sub: item.organization ?? "—",
                value: formatBytes(item.bytes),
                ratio: item.bytes / Math.max(1, ...overview.top_asns.map((entry) => entry.bytes)),
                href: `/explore?scope=flows&asn=${item.asn}`,
              }))}
            />
          )}
        </RankSection>
      </section>

      <section className="flex flex-col gap-3">
        <SectionHead
          title="Recent flows"
          description="Newest activity across the boundary"
          action={
            <Link to="/explore" className="inline-flex items-center gap-0.5 text-xs font-medium text-primary hover:underline">
              View all
              <ChevronRight className="size-3.5" />
            </Link>
          }
        />
        <div
          style={{ viewTransitionName: "flows-surface" }}
          onMouseEnter={() => {
            hoveringRows.current = true;
          }}
          onMouseLeave={() => {
            hoveringRows.current = false;
          }}
        >
          <Table>
            <TableHeader>
              <TableRow>
                {FLOW_COLUMNS.map((column) => (
                  <TableHead key={column.label}>{column.label}</TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {recent.length ? (
                recent.map((flow) => <FlowRow key={flow.id} flow={flow} onOpen={(id) => open({ kind: "flow", id })} />)
              ) : (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={FLOW_COLUMNS.length} className="h-24 text-center text-muted-foreground">
                    No flows observed yet
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>

        <motion.div
          ref={scrollTriggerRef}
          className="flex items-center justify-center gap-1.5 pt-0.5 text-2xs text-muted-foreground"
          initial={false}
        >
          <motion.span
            aria-hidden
            animate={reduceMotion ? undefined : { y: [0, 3, 0] }}
            transition={{ duration: 1.8, repeat: Infinity, ease: "easeInOut" }}
          >
            <ChevronDown className="size-3.5" />
          </motion.span>
          Keep scrolling to open the full flows ledger
        </motion.div>
      </section>
    </div>
  );
}

function RateCard({
  direction,
  title,
  subtitle,
  bps,
  total,
  packets,
  spark,
  className,
}: {
  direction: "inbound" | "outbound";
  title: string;
  subtitle: string;
  bps: number;
  total: string;
  packets: string;
  spark: number[];
  className?: string;
}) {
  const rate = formatRate(bps);
  return (
    <div className={cn("flex flex-col gap-3", className)}>
      <div className="flex items-center gap-2.5">
        <span
          className={cn(
            "grid size-9 shrink-0 place-items-center rounded-lg",
            direction === "inbound" ? "bg-series-inbound/10 text-series-inbound" : "bg-series-outbound/12 text-series-outbound",
          )}
        >
          <ArrowLeftRight
            className={cn("size-[19px]", direction === "outbound" && "-scale-x-100")}
            strokeWidth={1.8}
          />
        </span>
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          <p className="text-2xs text-muted-foreground">{subtitle}</p>
        </div>
        <span className="ml-auto inline-flex items-center gap-1.5 rounded-full bg-success/12 px-2 py-0.5 text-2xs font-medium text-success">
          <i className="size-1.5 rounded-full bg-success" />
          Live
        </span>
      </div>
      <div className="flex items-baseline gap-2">
        <SpringNumber
          value={Number(rate.value)}
          format={(value) => value.toFixed(rate.value.includes(".") ? 2 : 0)}
          className="text-[2.25rem] leading-none font-semibold tracking-[-0.025em] tabular-nums"
        />
        <span className="text-base font-medium text-muted-foreground">{rate.unit}</span>
      </div>
      <Sparkline values={spark.length > 1 ? spark : [1, 1]} series={direction} />
      <div className="flex gap-8 text-xs">
        <div>
          <span className="block text-2xs text-muted-foreground">Total in range</span>
          <strong className="font-semibold tabular-nums">{total}</strong>
        </div>
        <div>
          <span className="block text-2xs text-muted-foreground">Packets</span>
          <strong className="font-semibold tabular-nums">{packets}</strong>
        </div>
      </div>
    </div>
  );
}

function StatCards({ overview, activeFlows }: { overview: NonNullable<ReturnType<typeof useOverview>["data"]>; activeFlows: number }) {
  const health = overview.health;
  const visible = overview.domain_visibility;
  const map = health?.map;
  const stats = [
    {
      label: "Active flows",
      value: activeFlows,
      note: `${formatNumber(overview.totals.inbound.packets + overview.totals.outbound.packets)} packets observed`,
      spring: true,
    },
    {
      label: "Domain visibility",
      value: formatPercent(visible.ratio),
      note: visible.by_evidence.length
        ? `${visible.flows_with_domain} of ${visible.flows_total} flows · ${visible.by_evidence
            .map((entry) => `${evidenceLabel(entry.evidence)} ${entry.flows}`)
            .join(" · ")}`
        : `${visible.flows_with_domain} of ${visible.flows_total} flows carry evidence`,
      spring: false,
    },
    {
      label: "Map occupancy",
      value: map ? (map.entries / map.capacity < 0.01 ? "<1%" : `${Math.round((map.entries / map.capacity) * 100)}%`) : "—",
      note: map ? `${formatNumber(map.entries)} / ${formatNumber(map.capacity)} flow entries` : "Collector unavailable",
      spring: false,
    },
    {
      label: "Collector",
      value: health ? (health.state === "running" ? "Healthy" : health.state) : "Offline",
      note: health?.interfaces.length
        ? `Attached to ${health.interfaces.map((entry) => entry.name).join(", ")}`
        : "No interface attached",
      spring: false,
    },
  ];
  return (
    <>
      {stats.map((stat) => (
        <div key={stat.label} className="flex min-w-0 flex-col gap-0.5">
          <span className="text-2xs text-muted-foreground">{stat.label}</span>
          {stat.spring ? (
            <SpringNumber
              value={stat.value as number}
              format={(value) => String(Math.round(value))}
              className="truncate text-lg font-semibold tabular-nums"
            />
          ) : (
            <strong className="truncate text-lg font-semibold">{stat.value as string}</strong>
          )}
          <span className="truncate text-2xs text-muted-foreground">{stat.note}</span>
        </div>
      ))}
    </>
  );
}

function SectionHead({ title, description, action }: { title: string; description?: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-end justify-between gap-4">
      <div>
        <h2 className="text-sm font-semibold tracking-[0.01em]">{title}</h2>
        {description && <p className="mt-0.5 text-2xs text-muted-foreground">{description}</p>}
      </div>
      {action}
    </div>
  );
}

function RankSection({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-2.5">
      <div>
        <h2 className="text-sm font-semibold">{title}</h2>
        <p className="text-2xs text-muted-foreground">{subtitle}</p>
      </div>
      {children}
    </div>
  );
}

function SkeletonRows({ count }: { count: number }) {
  return (
    <div className="flex flex-col gap-2 py-1">
      {Array.from({ length: count }, (_, index) => (
        <Skeleton key={index} className="h-8" />
      ))}
    </div>
  );
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "The local agent did not respond.";
}

function CollectionNotice({
  status,
  health,
  error: requestError,
}: {
  status: ServiceStatus | undefined;
  health: CollectorHealth | null;
  error?: string;
}) {
  if (requestError) {
    return (
      <div className="flex items-start gap-2.5 rounded-lg border border-destructive/30 bg-destructive/8 px-3.5 py-2.5">
        <TriangleAlert className="mt-px size-4 shrink-0 text-destructive" />
        <div className="min-w-0">
          <strong className="block text-xs font-medium text-destructive">Agent unavailable</strong>
          <p className="mt-0.5 text-2xs leading-relaxed break-words text-muted-foreground">{requestError}</p>
        </div>
      </div>
    );
  }
  const error = status?.collector_error ?? status?.database_error;
  if (error) {
    return (
      <div className="flex items-start gap-2.5 rounded-lg border border-destructive/30 bg-destructive/8 px-3.5 py-2.5">
        <TriangleAlert className="mt-px size-4 shrink-0 text-destructive" />
        <div className="min-w-0">
          <strong className="block text-xs font-medium text-destructive">Collection unavailable</strong>
          <p className="mt-0.5 text-2xs leading-relaxed break-words text-muted-foreground">{error}</p>
        </div>
      </div>
    );
  }
  if (health && health.state !== "running") {
    return (
      <div className="flex items-start gap-2.5 rounded-lg border border-warning/30 bg-warning/8 px-3.5 py-2.5">
        <TriangleAlert className="mt-px size-4 shrink-0 text-warning" />
        <div className="min-w-0">
          <strong className="block text-xs font-medium">Collector {health.state}</strong>
          <p className="mt-0.5 text-2xs text-muted-foreground">
            Attached interfaces: {health.interfaces.map((entry) => entry.name).join(", ") || "none"}.
          </p>
        </div>
      </div>
    );
  }
  const gaps = health?.gaps ?? [];
  if (gaps.length) {
    const open = gaps.some((gap) => gap.ended_at === null);
    const latest = gaps[gaps.length - 1];
    return (
      <div className="flex items-start gap-2.5 rounded-lg border border-warning/30 bg-warning/8 px-3.5 py-2.5">
        <TriangleAlert className="mt-px size-4 shrink-0 text-warning" />
        <div className="min-w-0">
          <strong className="block text-xs font-medium">
            {open ? "Observation gap in progress" : `${gaps.length} observation gap${gaps.length > 1 ? "s" : ""} recorded`}
          </strong>
          <p className="mt-0.5 text-2xs text-muted-foreground">
            {open
              ? "Traffic during this interval may be incomplete."
              : `Last gap started ${relativeTime(latest.started_at)}.`}
          </p>
        </div>
      </div>
    );
  }
  return null;
}
