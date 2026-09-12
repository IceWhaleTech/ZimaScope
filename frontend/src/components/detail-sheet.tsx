/**
 * Detail panel: a right-side material Sheet. All four details answer the same
 * questions — what is it, how much traffic, what evidence do we have, and
 * where can I go next — but only one answer at a time: a compact summary
 * stays visible, a segmented control switches between focused sections, and
 * long lists are capped with a "view all flows" exit instead of scrolling a
 * wall of rows.
 */

import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router";
import { motion } from "motion/react";
import { toast } from "sonner";
import { ArrowLeftRight, Boxes, ChevronRight, Globe, Terminal, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { TimelineChart } from "@/components/charts";
import { CountryLabel, DirectionBadge, EvidenceChip, ScopeChip, StateBadge } from "@/components/flow-bits";
import { Segmented } from "@/components/segmented";
import { DefList, StatTiles } from "@/components/stat-tiles";
import { useDetails } from "@/hooks/use-details";
import {
  useApplication,
  useApplicationTimeline,
  useDomain,
  useDomainTimeline,
  useDomains,
  useEndpoint,
  useEndpointTimeline,
  useFlow,
} from "@/hooks/use-data";
import {
  formatBytes,
  formatClock,
  formatDuration,
  formatNumber,
  relativeTime,
  evidenceTitle,
} from "@/lib/format";
import type { ApplicationDetail, DomainDetail, EndpointDetail, Flow, TimeRange } from "@/types";

const enter = {
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.28, ease: [0.32, 0.72, 0, 1] as const },
};

/** Rows shown per list before the "view all flows" exit takes over. */
const LIST_LIMIT = 6;

type Tab = { value: string; label: string };

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
        {target?.kind === "application" && (
          <ApplicationDetailPanel key={`application:${target.id}`} id={target.id} />
        )}
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

/** One section at a time: the segmented control switches the visible block. */
function DetailTabs({
  tabs,
  value,
  onChange,
}: {
  tabs: Tab[];
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <div className="flex min-w-0 overflow-x-auto pb-0.5">
      <Segmented ariaLabel="Detail sections" options={tabs} value={value} onChange={onChange} />
    </div>
  );
}

/** Caption + content inside a tab; the tab label already names the section. */
function TabSection({ caption, children }: { caption: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2.5">
      <p className="text-2xs text-muted-foreground">{caption}</p>
      {children}
    </section>
  );
}

/** Notes that a list is truncated; the footer button opens the full view. */
function TruncationNote({ shown, total }: { shown: number; total: number }) {
  if (total <= shown) return null;
  return (
    <p className="pt-1 text-2xs text-muted-foreground">
      Showing {shown} of {total} — open all flows for the rest.
    </p>
  );
}

const TREND_RANGES = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

/** Bytes observed for one Endpoint, Domain or Application over the range. */
function EntityTrend({
  kind,
  target,
}: {
  kind: "endpoint" | "domain" | "application";
  target: string;
}) {
  const [range, setRange] = useState<TimeRange>("15m");
  const endpointQuery = useEndpointTimeline(kind === "endpoint" ? target : null, range);
  const domainQuery = useDomainTimeline(kind === "domain" ? target : null, range);
  const applicationQuery = useApplicationTimeline(kind === "application" ? target : null, range);
  const query =
    kind === "endpoint" ? endpointQuery : kind === "domain" ? domainQuery : applicationQuery;

  return (
    <TabSection caption="Bytes at the device boundary per interval">
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
    </TabSection>
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

const FLOW_TABS: Tab[] = [
  { value: "summary", label: "Summary" },
  { value: "remote", label: "Remote" },
  { value: "path", label: "Path" },
];

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
  const { close, open } = useDetails();
  const navigate = useNavigate();
  const [tab, setTab] = useState("summary");
  const domain = flow.domains[0];
  const network = flow.remote_profile;
  const source = `${flow.source.address}${flow.source.port ? `:${flow.source.port}` : ""}`;
  const destination = `${flow.destination.address}${flow.destination.port ? `:${flow.destination.port}` : ""}`;
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-4 p-4">
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

        <DetailTabs tabs={FLOW_TABS} value={tab} onChange={setTab} />

        <motion.div key={tab} {...enter} className="flex flex-col gap-4">
          {tab === "summary" && (
            <TabSection caption="Evidence linking this flow to a name">
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
            </TabSection>
          )}

          {tab === "remote" && (
            <TabSection caption="Locally enriched IP metadata">
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
            </TabSection>
          )}

          {tab === "path" && (
            <TabSection caption="Direction relative to the device boundary">
              <DefList
                rows={[
                  ...(flow.application
                    ? [
                        {
                          label: "Application",
                          value: (
                            <button
                              type="button"
                              onClick={() => open({ kind: "application", id: flow.application!.id })}
                              className="inline-flex max-w-full items-center gap-1 truncate text-xs font-medium text-foreground underline-offset-2 hover:underline"
                              title={flow.application.id}
                            >
                              {flow.application.kind === "container" ? (
                                <Boxes className="size-3 shrink-0" />
                              ) : (
                                <Terminal className="size-3 shrink-0" />
                              )}
                              <span className="truncate">{flow.application.name}</span>
                            </button>
                          ),
                        },
                      ]
                    : []),
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
            </TabSection>
          )}
        </motion.div>

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

const ENDPOINT_TABS: Tab[] = [
  { value: "traffic", label: "Traffic" },
  { value: "ports", label: "Ports" },
  { value: "domains", label: "Domains" },
  { value: "network", label: "Network" },
];

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
  const [tab, setTab] = useState("traffic");
  const maxPort = Math.max(1, ...detail.ports.map((port) => port.bytes));
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-4 p-4">
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

        <DetailTabs tabs={ENDPOINT_TABS} value={tab} onChange={setTab} />

        <motion.div key={tab} {...enter} className="flex flex-col gap-4">
          {tab === "traffic" && <EntityTrend kind="endpoint" target={detail.address} />}

          {tab === "ports" && (
            <TabSection caption="Observed usage by port and direction">
              {detail.ports.length ? (
                <>
                  <ul className="flex flex-col gap-2.5">
                    {detail.ports.slice(0, LIST_LIMIT).map((port) => (
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
                  <TruncationNote shown={Math.min(LIST_LIMIT, detail.ports.length)} total={detail.ports.length} />
                </>
              ) : (
                <p className="text-xs text-muted-foreground">No port data</p>
              )}
            </TabSection>
          )}

          {tab === "domains" && (
            <TabSection caption="Names linked to this endpoint">
              {detail.domains.length ? (
                <>
                  <ul className="flex flex-col">
                    {detail.domains.slice(0, LIST_LIMIT).map((ref) => (
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
                  <TruncationNote shown={Math.min(LIST_LIMIT, detail.domains.length)} total={detail.domains.length} />
                </>
              ) : (
                <p className="text-xs text-muted-foreground">No domain evidence is associated with this endpoint.</p>
              )}
            </TabSection>
          )}

          {tab === "network" && (
            <TabSection caption="From the local enrichment database">
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
            </TabSection>
          )}
        </motion.div>

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

const DOMAIN_TABS: Tab[] = [
  { value: "traffic", label: "Traffic" },
  { value: "evidence", label: "Evidence" },
  { value: "addresses", label: "Addresses" },
  { value: "destinations", label: "Destinations" },
];

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
  const [tab, setTab] = useState("traffic");
  const evidenceTotal = Math.max(1, detail.evidence.reduce((sum, item) => sum + item.flows, 0));
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-4 p-4">
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

        <DetailTabs tabs={DOMAIN_TABS} value={tab} onChange={setTab} />

        <motion.div key={tab} {...enter} className="flex flex-col gap-4">
          {tab === "traffic" && <EntityTrend kind="domain" target={detail.domain} />}

          {tab === "evidence" && (
            <TabSection caption="How this name was observed">
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
            </TabSection>
          )}

          {tab === "addresses" && (
            <TabSection caption="IPs seen carrying this name">
              {detail.addresses.length ? (
                <>
                  <ul className="flex flex-col">
                    {detail.addresses.slice(0, LIST_LIMIT).map((address) => (
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
                  <TruncationNote shown={Math.min(LIST_LIMIT, detail.addresses.length)} total={detail.addresses.length} />
                </>
              ) : (
                <p className="text-xs text-muted-foreground">No addresses observed yet.</p>
              )}
            </TabSection>
          )}

          {tab === "destinations" && (
            <TabSection caption="Countries and networks serving this name">
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
            </TabSection>
          )}
        </motion.div>

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

/* ---------------------------- Application --------------------------------- */

const APPLICATION_TABS: Tab[] = [
  { value: "traffic", label: "Traffic" },
  { value: "destinations", label: "Destinations" },
  { value: "domains", label: "Domains" },
  { value: "identity", label: "Identity" },
];

function ApplicationDetailPanel({ id }: { id: string }) {
  const query = useApplication(id);
  const { close } = useDetails();
  useEffect(() => {
    if (query.isSuccess && !query.data) {
      toast.error("Application not found in retained history");
      close();
    }
  }, [query.isSuccess, query.data, close]);
  const detail = query.data;
  return (
    <>
      <PanelHead
        eyebrow="Application detail"
        title={detail?.name ?? id}
        subtitle={
          detail
            ? `${detail.kind} · ${detail.flow_count} flows · seen ${relativeTime(detail.last_seen)}`
            : "Process attributed through observed socket ownership"
        }
      />
      {detail ? <ApplicationDetailBody detail={detail} /> : query.isLoading ? <PanelLoading /> : null}
    </>
  );
}

function ApplicationDetailBody({ detail }: { detail: ApplicationDetail }) {
  const { close, open } = useDetails();
  const navigate = useNavigate();
  const [tab, setTab] = useState("traffic");
  const Icon = detail.kind === "container" ? Boxes : Terminal;
  const domains = useDomains({
    application_id: detail.id,
    sort: "-bytes",
    limit: LIST_LIMIT,
  });
  return (
    <ScrollArea className="min-h-0 min-w-0 max-w-full flex-1 overflow-hidden">
      <motion.div {...enter} className="flex w-full min-w-0 max-w-full flex-col gap-4 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-md border border-border/60 px-2 py-0.5 text-2xs text-muted-foreground">
            <Icon className="size-3" />
            {detail.kind === "container" ? "Container" : "Process"}
          </span>
        </div>

        <StatTiles
          tiles={[
            { label: "Total traffic", value: formatBytes(detail.bytes) },
            { label: "Packets", value: formatNumber(detail.packets) },
            { label: "Flows", value: String(detail.flow_count) },
            { label: "First seen", value: relativeTime(detail.first_seen) },
          ]}
        />

        <DetailTabs tabs={APPLICATION_TABS} value={tab} onChange={setTab} />

        <motion.div key={tab} {...enter} className="flex flex-col gap-4">
          {tab === "traffic" && <EntityTrend kind="application" target={detail.id} />}

          {tab === "destinations" && (
            <TabSection caption="Peer addresses this Application talked to, by traffic">
              {detail.destinations.length ? (
                <>
                  <ul className="flex flex-col">
                    {detail.destinations.slice(0, LIST_LIMIT).map((destination) => (
                      <li key={destination.address}>
                        <button
                          type="button"
                          onClick={() => open({ kind: "endpoint", address: destination.address })}
                          className="flex w-full items-center gap-2 rounded-md px-1 py-2 text-left transition-colors hover:bg-accent"
                        >
                          <span className="flex min-w-0 flex-1 flex-col">
                            <span className="truncate font-mono text-xs font-medium">
                              {destination.address}
                            </span>
                            <span className="truncate text-2xs text-muted-foreground">
                              {destination.country ? (
                                <CountryLabel country={destination.country} />
                              ) : (
                                (destination.organization ?? "Not enriched")
                              )}
                              {destination.domains.length
                                ? ` · ${destination.domains
                                    .slice(0, 3)
                                    .map((domain) => domain.domain)
                                    .join(" · ")}${destination.domains.length > 3 ? ` +${destination.domains.length - 3}` : ""}`
                                : " · No domain evidence"}
                            </span>
                          </span>
                          <span className="shrink-0 text-2xs tabular-nums text-muted-foreground">
                            ↓{formatBytes(destination.traffic.inbound.bytes)} ↑
                            {formatBytes(destination.traffic.outbound.bytes)}
                          </span>
                          <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
                        </button>
                      </li>
                    ))}
                  </ul>
                  <TruncationNote
                    shown={Math.min(LIST_LIMIT, detail.destinations.length)}
                    total={detail.destinations.length}
                  />
                </>
              ) : (
                <p className="text-xs text-muted-foreground">
                  No destination was observed for this Application yet.
                </p>
              )}
            </TabSection>
          )}

          {tab === "domains" && (
            <TabSection caption="Names contacted by this Application, by traffic">
              {domains.data?.items.length ? (
                <ul className="flex flex-col">
                  {domains.data.items.map((summary) => (
                    <li key={summary.domain}>
                      <button
                        type="button"
                        onClick={() => open({ kind: "domain", name: summary.domain })}
                        className="flex w-full items-center gap-2 rounded-md px-1 py-2 text-left transition-colors hover:bg-accent"
                      >
                        <span className="min-w-0 flex-1 truncate text-xs font-medium">
                          {summary.domain}
                        </span>
                        <span className="flex shrink-0 items-center gap-1">
                          {summary.evidence.map((evidence) => (
                            <EvidenceChip
                              key={evidence}
                              evidence={evidence}
                              confidence={evidence === "dns" ? "inferred" : "direct"}
                            />
                          ))}
                        </span>
                        <span className="shrink-0 text-2xs tabular-nums text-muted-foreground">
                          ↑{formatBytes(summary.traffic.outbound.bytes)}
                        </span>
                        <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
                      </button>
                    </li>
                  ))}
                </ul>
              ) : domains.isLoading ? (
                <Skeleton className="h-16 w-full" />
              ) : (
                <p className="text-xs text-muted-foreground">
                  No Associated Domain was observed for this Application yet.
                </p>
              )}
            </TabSection>
          )}

          {tab === "identity" && (
            <TabSection caption="Observed from socket ownership; location is best-effort">
              <DefList
                rows={[
                  { label: "Process name", value: detail.comm ?? detail.name },
                  {
                    label: "Location",
                    value: detail.exe ? (
                      <span className="font-mono text-xs">{detail.exe}</span>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    ),
                  },
                  { label: "UID", value: detail.uid !== null ? String(detail.uid) : "—" },
                  ...(detail.container_id
                    ? [
                        {
                          label: "Container",
                          value: <span className="font-mono text-xs">{detail.container_id}</span>,
                        },
                      ]
                    : []),
                ]}
              />
            </TabSection>
          )}
        </motion.div>

        <Button
          onClick={() => {
            close();
            navigate(`/flows?application=${encodeURIComponent(detail.id)}`);
          }}
        >
          <ArrowLeftRight className="size-3.5" />
          View all flows
        </Button>
      </motion.div>
    </ScrollArea>
  );
}
