/**
 * Detail panel: a right-side material Sheet. All three details answer the
 * same questions — what is it, how much traffic, what evidence do we have,
 * and where can I go next.
 */

import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { motion } from "motion/react";
import { toast } from "sonner";
import { ArrowLeftRight, ChevronRight, Globe, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { TimelineChart } from "@/components/charts";
import { CountryLabel, DirectionBadge, EvidenceChip, ScopeChip, StateBadge } from "@/components/flow-bits";
import { Segmented } from "@/components/segmented";
import { DefList, PanelSection, StatTiles } from "@/components/stat-tiles";
import { useDetails } from "@/hooks/use-details";
import { useDomain, useDomainTimeline, useEndpoint, useEndpointTimeline, useFlow } from "@/hooks/use-data";
import {
  formatBytes,
  formatClock,
  formatDuration,
  formatNumber,
  relativeTime,
  evidenceTitle,
} from "@/lib/format";
import type { DomainDetail, EndpointDetail, Flow, TimeRange } from "@/types";

const enter = {
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.28, ease: [0.32, 0.72, 0, 1] as const },
};

export function DetailSheet() {
  const { target, close } = useDetails();
  return (
    <Sheet open={Boolean(target)} onOpenChange={(open) => !open && close()}>
      <SheetContent
        side="right"
        showCloseButton={false}
        className="material-chrome min-w-0 max-w-none gap-0 overflow-hidden border-0 p-0"
        style={{ width: "min(26rem, 100dvw)", maxWidth: "100dvw", right: 0 }}
      >
        <button
          type="button"
          onClick={close}
          aria-label="Close details"
          className="absolute top-4 right-4 z-10 grid size-7 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:ring-[3px] focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <X className="size-4" />
        </button>
        {target?.kind === "flow" && <FlowDetail key={`flow:${target.id}`} id={target.id} />}
        {target?.kind === "endpoint" && (
          <EndpointDetail key={`endpoint:${target.address}`} address={target.address} />
        )}
        {target?.kind === "domain" && <DomainDetail key={`domain:${target.name}`} name={target.name} />}
      </SheetContent>
    </Sheet>
  );
}

function PanelLoading() {
  return (
    <div className="flex flex-1 flex-col gap-2.5 p-4">
      {[0, 1, 2, 3, 4].map((row) => (
        <Skeleton key={row} className="h-6 w-full" />
      ))}
    </div>
  );
}

function PanelMessage({ message }: { message: string }) {
  return (
    <div className="flex flex-1 items-start p-4">
      <p className="rounded-lg bg-muted/60 px-3 py-2.5 text-xs leading-relaxed text-muted-foreground">{message}</p>
    </div>
  );
}

function PanelHead({ eyebrow, title, subtitle }: { eyebrow: string; title: string; subtitle?: string }) {
  return (
    <SheetHeader className="gap-1 border-b border-border/60 p-4 pr-12">
      <p className="text-2xs font-medium tracking-[0.05em] text-muted-foreground uppercase">{eyebrow}</p>
      <SheetTitle className="truncate text-base font-semibold tracking-[0.01em]">{title}</SheetTitle>
      {subtitle && <SheetDescription className="truncate text-xs">{subtitle}</SheetDescription>}
    </SheetHeader>
  );
}

const TREND_RANGES = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

/** Bytes observed for one Endpoint or Domain over the selected range. */
function EntityTrend({ kind, target }: { kind: "endpoint" | "domain"; target: string }) {
  const [range, setRange] = useState<TimeRange>("15m");
  const endpointQuery = useEndpointTimeline(kind === "endpoint" ? target : null, range);
  const domainQuery = useDomainTimeline(kind === "domain" ? target : null, range);
  const query = kind === "endpoint" ? endpointQuery : domainQuery;

  return (
    <PanelSection title="Traffic trend" subtitle="Bytes at the device boundary per interval">
      <div className="flex min-w-0 justify-end">
        <Segmented
          ariaLabel="Trend range"
          options={TREND_RANGES}
          value={range}
          onChange={(value) => setRange(value as TimeRange)}
        />
      </div>
      {query.data ? (
        <TimelineChart points={query.data.points} heightClass="h-32" />
      ) : (
        <Skeleton className="h-32 w-full" />
      )}
      <div className="flex items-center gap-4 text-2xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <i className="size-1.5 rounded-full bg-series-inbound" />Inbound
        </span>
        <span className="inline-flex items-center gap-1.5">
          <i className="size-1.5 rounded-full bg-series-outbound" />Outbound
        </span>
      </div>
    </PanelSection>
  );
}

/* ------------------------------- Flow ------------------------------------- */

function FakeIpNote() {
  return (
    <p className="rounded-lg border border-warning/30 bg-warning/8 px-2.5 py-2 text-2xs leading-relaxed text-muted-foreground">
      <strong className="font-medium text-warning">Fake IP.</strong> A local proxy issued this
      address and dials the real destination itself, so country and network cannot be attributed
      here. The Associated Domain is the reliable part of this Flow.
    </p>
  );
}

function FlowDetail({ id }: { id: string }) {
  const query = useFlow(id);
  const flow = query.data;
  return (
    <>
      <PanelHead
        eyebrow="Flow detail"
        title={flow ? (flow.domains[0]?.domain ?? flow.remote.address) : query.isError ? "Not found" : "Loading…"}
        subtitle={
          flow
            ? `${flow.remote.address}${flow.remote.port ? `:${flow.remote.port}` : ""} · seen ${relativeTime(flow.last_seen)}`
            : undefined
        }
      />
      {flow ? <FlowDetailBody flow={flow} /> : query.isError ? <PanelMessage message="This flow is no longer retained." /> : <PanelLoading />}
    </>
  );
}

function FlowDetailBody({ flow }: { flow: Flow }) {
  const { close } = useDetails();
  const navigate = useNavigate();
  const domain = flow.domains[0];
  const network = flow.remote_profile;
  const source = `${flow.source.address}${flow.source.port ? `:${flow.source.port}` : ""}`;
  const destination = `${flow.destination.address}${flow.destination.port ? `:${flow.destination.port}` : ""}`;
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <StateBadge state={flow.state} />
          <DirectionBadge direction={flow.direction} />
          <ScopeChip scope={network.scope} />
        </div>

        <StatTiles
          tiles={[
            { label: "Total traffic", value: formatBytes(flow.bytes) },
            { label: "Packets", value: formatNumber(flow.packets) },
            { label: "Duration", value: formatDuration(flow.duration_ms) },
            { label: "Last seen", value: relativeTime(flow.last_seen) },
          ]}
        />

        <PanelSection title="Associated domain" subtitle="Evidence linking this flow to a name">
          {domain ? (
            <div className="rounded-lg border border-border/60 p-3">
              <div className="flex items-center justify-between gap-2">
                <strong className="truncate text-xs">{domain.domain}</strong>
                <EvidenceChip evidence={domain.evidence} confidence={domain.confidence} />
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">
                {evidenceTitle(domain.evidence)} · {domain.confidence === "direct" ? "Direct" : "Inferred"} association.
              </p>
            </div>
          ) : (
            <div className="rounded-lg border border-border/60 bg-muted/50 p-3">
              <div className="flex items-center justify-between gap-2">
                <strong className="text-xs">Domain unavailable</strong>
                <span className="text-2xs text-muted-foreground">No evidence</span>
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">
                No DNS answer, TLS SNI or HTTP Host was observed for this flow. Common reasons: cached DNS, DoH/DoT,
                ECH, QUIC, fragmentation, or the connection predates collection.
              </p>
            </div>
          )}
        </PanelSection>

        <PanelSection title="Remote profile" subtitle="Locally enriched IP metadata">
          <DefList
            rows={[
              { label: "Address", value: <span className="font-mono text-xs">{network.address}</span> },
              { label: "Address scope", value: <ScopeChip scope={network.scope} /> },
              {
                label: "Country / region",
                value: network.country ? (
                  <span className="inline-flex items-center gap-1.5">
                    <CountryLabel country={network.country} />
                    {network.region && <span className="text-muted-foreground">· {network.region}</span>}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Not enriched</span>
                ),
              },
              { label: "ASN", value: network.asn ? `AS${network.asn}` : <span className="text-muted-foreground">—</span> },
              { label: "Organization", value: network.organization ?? "—" },
              {
                label: "Database",
                value: network.database_version ?? <span className="text-muted-foreground">Unavailable</span>,
              },
            ]}
          />
          {network.scope === "fake_ip" ? (
            <FakeIpNote />
          ) : (
            <p className="text-2xs text-muted-foreground">
              An ASN organization describes network ownership, not the domain owner.
            </p>
          )}
        </PanelSection>

        <PanelSection title="Path" subtitle="Direction relative to the device boundary">
          <DefList
            rows={[
              {
                label: flow.direction === "outbound" ? "From" : "Remote source",
                value: <span className="font-mono text-xs">{source}</span>,
              },
              {
                label: flow.direction === "outbound" ? "Remote destination" : "To",
                value: <span className="font-mono text-xs">{destination}</span>,
              },
              {
                label: "First seen",
                value: `${formatClock(flow.first_seen)} · ${relativeTime(flow.first_seen)}`,
              },
              {
                label: "End reason",
                value: flow.end_reason ? flow.end_reason.replace("_", " ") : "—",
              },
            ]}
          />
        </PanelSection>

        <div className="flex gap-2">
          <Button
            onClick={() => {
              close();
              navigate(`/flows?ip=${encodeURIComponent(flow.remote.address)}`);
            }}
          >
            <ArrowLeftRight className="size-3.5" />
            Filter by endpoint
          </Button>
          {domain && (
            <Button
              variant="secondary"
              onClick={() => {
                close();
                navigate(`/flows?domain=${encodeURIComponent(domain.domain)}`);
              }}
            >
              <Globe className="size-3.5" />
              Filter by domain
            </Button>
          )}
        </div>
      </motion.div>
    </ScrollArea>
  );
}

/* ------------------------------ Endpoint ---------------------------------- */

function EndpointDetail({ address }: { address: string }) {
  const query = useEndpoint(address);
  const { close } = useDetails();
  useEffect(() => {
    if (query.isSuccess && !query.data) {
      toast.error("Endpoint not found in retained history");
      close();
    }
  }, [query.isSuccess, query.data, close]);
  const detail = query.data;
  return (
    <>
      <PanelHead
        eyebrow="Endpoint detail"
        title={address}
        subtitle={detail ? `${detail.flow_count} flows · seen ${relativeTime(detail.last_seen)}` : "Locally enriched IP profile"}
      />
      {detail ? <EndpointDetailBody detail={detail} /> : query.isLoading ? <PanelLoading /> : null}
    </>
  );
}

function EndpointDetailBody({ detail }: { detail: EndpointDetail }) {
  const { close, open } = useDetails();
  const navigate = useNavigate();
  const maxPort = Math.max(1, ...detail.ports.map((port) => port.bytes));
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <ScopeChip scope={detail.profile.scope} />
          {detail.profile.country && <CountryLabel country={detail.profile.country} />}
        </div>

        <StatTiles
          tiles={[
            { label: "Total traffic", value: formatBytes(detail.bytes) },
            { label: "Packets", value: formatNumber(detail.packets) },
            { label: "Flows", value: String(detail.flow_count) },
            { label: "First seen", value: relativeTime(detail.first_seen) },
          ]}
        />

        <EntityTrend kind="endpoint" target={detail.address} />

        <PanelSection title="IP profile" subtitle="From the local enrichment database">
          <DefList
            rows={[
              { label: "Organization", value: detail.profile.organization ?? "—" },
              { label: "ASN", value: detail.profile.asn ? `AS${detail.profile.asn}` : "—" },
              {
                label: "Country / region",
                value: detail.profile.country ? (
                  <span className="inline-flex items-center gap-1.5">
                    <CountryLabel country={detail.profile.country} />
                    {detail.profile.region && <span className="text-muted-foreground">· {detail.profile.region}</span>}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Not enriched</span>
                ),
              },
              {
                label: "Last seen",
                value: `${formatClock(detail.last_seen)} · ${relativeTime(detail.last_seen)}`,
              },
            ]}
          />
          {detail.profile.scope === "fake_ip" && <FakeIpNote />}
        </PanelSection>

        <PanelSection title="Ports" subtitle="Observed usage by port and direction">
          {detail.ports.length ? (
            <ul className="flex flex-col gap-2.5">
              {detail.ports.slice(0, 8).map((port) => (
                <li key={`${port.port}-${port.protocol}-${port.direction}`} className="flex flex-col gap-1">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="font-mono text-xs font-medium">{port.port || "—"}</span>
                    <strong className="text-xs tabular-nums">{formatBytes(port.bytes)}</strong>
                  </div>
                  <UsageBar ratio={port.bytes / maxPort} />
                  <span className="text-2xs text-muted-foreground">
                    {port.protocol.toUpperCase()} · {port.direction} · {port.flow_count} flows
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">No port data</p>
          )}
        </PanelSection>

        <PanelSection title="Associated domains" subtitle="Names linked to this endpoint">
          {detail.domains.length ? (
            <ul className="flex flex-col">
              {detail.domains.slice(0, 8).map((ref) => (
                <li key={ref.domain}>
                  <button
                    type="button"
                    onClick={() => open({ kind: "domain", name: ref.domain })}
                    className="flex w-full items-center gap-2 rounded-md px-1 py-2 text-left transition-colors hover:bg-accent"
                  >
                    <span className="min-w-0 flex-1 truncate text-xs font-medium">{ref.domain}</span>
                    <EvidenceChip evidence={ref.evidence} confidence={ref.confidence} />
                    <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">No domain evidence is associated with this endpoint.</p>
          )}
        </PanelSection>

        <Button
          onClick={() => {
            close();
            navigate(`/flows?ip=${encodeURIComponent(detail.address)}`);
          }}
        >
          <ArrowLeftRight className="size-3.5" />
          View all flows
        </Button>
      </motion.div>
    </ScrollArea>
  );
}

/* ------------------------------- Domain ----------------------------------- */

function DomainDetail({ name }: { name: string }) {
  const query = useDomain(name);
  const { close } = useDetails();
  useEffect(() => {
    if (query.isSuccess && !query.data) {
      toast.error("Domain not found in retained history");
      close();
    }
  }, [query.isSuccess, query.data, close]);
  const detail = query.data;
  return (
    <>
      <PanelHead
        eyebrow="Domain detail"
        title={name}
        subtitle={detail ? `${detail.flow_count} flows · seen ${relativeTime(detail.last_seen)}` : "Associated domain evidence"}
      />
      {detail ? <DomainDetailBody detail={detail} /> : query.isLoading ? <PanelLoading /> : null}
    </>
  );
}

function DomainDetailBody({ detail }: { detail: DomainDetail }) {
  const { close, open } = useDetails();
  const navigate = useNavigate();
  const evidenceTotal = Math.max(1, detail.evidence.reduce((sum, item) => sum + item.flows, 0));
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          {detail.evidence.map((item) => (
            <EvidenceChip key={item.evidence} evidence={item.evidence} />
          ))}
        </div>

        <StatTiles
          tiles={[
            { label: "Total traffic", value: formatBytes(detail.bytes) },
            { label: "Packets", value: formatNumber(detail.packets) },
            { label: "Flows", value: String(detail.flow_count) },
            { label: "First seen", value: relativeTime(detail.first_seen) },
          ]}
        />

        <EntityTrend kind="domain" target={detail.domain} />

        <PanelSection title="Evidence" subtitle="How this name was observed">
          <ul className="flex flex-col gap-2.5">
            {detail.evidence.map((item) => (
              <li key={item.evidence} className="flex flex-col gap-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-xs font-medium">
                    {item.evidence === "dns" ? "DNS" : item.evidence === "tls_sni" ? "TLS SNI" : "HTTP Host"}
                  </span>
                  <strong className="text-xs tabular-nums">{item.flows}</strong>
                </div>
                <UsageBar ratio={item.flows / evidenceTotal} />
                <span className="text-2xs text-muted-foreground">{evidenceTitle(item.evidence)}</span>
              </li>
            ))}
          </ul>
        </PanelSection>

        <PanelSection title="Resolved addresses" subtitle="IPs seen carrying this name">
          <ul className="flex flex-col">
            {detail.addresses.slice(0, 8).map((address) => (
              <li key={address.address}>
                <button
                  type="button"
                  onClick={() => open({ kind: "endpoint", address: address.address })}
                  className="flex w-full items-center gap-2 rounded-md px-1 py-2 text-left transition-colors hover:bg-accent"
                >
                  <span className="flex min-w-0 flex-1 flex-col">
                    <span className="truncate font-mono text-xs font-medium">{address.address}</span>
                    <span className="truncate text-2xs text-muted-foreground">
                      {address.organization ?? "—"}
                      {address.country ? ` · ${address.country}` : ""}
                    </span>
                  </span>
                  <span className="text-xs tabular-nums text-muted-foreground">{formatBytes(address.bytes)}</span>
                  <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
                </button>
              </li>
            ))}
          </ul>
        </PanelSection>

        <PanelSection title="Destinations" subtitle="Countries and networks serving this name">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="mb-1 text-2xs font-medium text-muted-foreground">Countries</h4>
              {detail.countries.length ? (
                detail.countries.map((item) => (
                  <p key={item.country} className="flex items-center justify-between gap-2 py-0.5 text-xs">
                    <CountryLabel country={item.country} />
                    <span className="font-medium tabular-nums">{formatBytes(item.bytes)}</span>
                  </p>
                ))
              ) : (
                <p className="text-xs text-muted-foreground">—</p>
              )}
            </div>
            <div>
              <h4 className="mb-1 text-2xs font-medium text-muted-foreground">Networks</h4>
              {detail.asns.length ? (
                detail.asns.map((item) => (
                  <p key={item.asn} className="flex items-center justify-between gap-2 py-0.5 text-xs">
                    <span className="truncate">AS{item.asn}</span>
                    <span className="font-medium tabular-nums">{formatBytes(item.bytes)}</span>
                  </p>
                ))
              ) : (
                <p className="text-xs text-muted-foreground">—</p>
              )}
            </div>
          </div>
        </PanelSection>

        <Button
          onClick={() => {
            close();
            navigate(`/flows?domain=${encodeURIComponent(detail.domain)}`);
          }}
        >
          <ArrowLeftRight className="size-3.5" />
          View all flows
        </Button>
      </motion.div>
    </ScrollArea>
  );
}

function UsageBar({ ratio }: { ratio: number }) {
  return (
    <div className="h-1 overflow-hidden rounded-full bg-muted">
      <div
        className="h-full rounded-full bg-primary/50"
        style={{ width: `${Math.max(2, Math.min(100, ratio * 100)).toFixed(1)}%` }}
      />
    </div>
  );
}
