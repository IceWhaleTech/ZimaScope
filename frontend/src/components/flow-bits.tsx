/**
 * Small semantic markers shared by tables and detail panels: flow state,
 * direction, domain evidence, address scope. Color is used for meaning only.
 */

import { ArrowDown, ArrowDownLeft, ArrowUp, ArrowUpRight } from "lucide-react";
import { cn } from "@/lib/utils";
import { evidenceTitle, flagEmoji, formatBytes, formatNumber, scopeLabel } from "@/lib/format";
import type { Confidence, Counters, Evidence, FlowState, Scope } from "@/types";

export function StateBadge({ state }: { state: FlowState }) {
  const active = state === "active";
  return (
    <span className="inline-flex items-center gap-1.5 text-sm font-medium whitespace-nowrap">
      <FlowStateDot state={state} />
      <span className={active ? "text-foreground" : "text-muted-foreground"}>
        {active ? "Active" : "Ended"}
      </span>
    </span>
  );
}

/** Dot-only flow state marker for dense table rows. */
export function FlowStateDot({ state }: { state: FlowState }) {
  return (
    <span
      title={state === "active" ? "Active" : "Ended"}
      className={cn(
        "size-1.5 shrink-0 rounded-full",
        state === "active" ? "bg-success" : "bg-muted-foreground/40",
      )}
    />
  );
}

export function DirectionBadge({ direction }: { direction: string }) {
  const outbound = direction === "outbound";
  const Icon = outbound ? ArrowUpRight : ArrowDownLeft;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-sm font-medium whitespace-nowrap",
        outbound ? "bg-series-outbound/12 text-series-outbound" : "bg-series-inbound/10 text-series-inbound",
      )}
    >
      <Icon className="size-3" strokeWidth={2.2} />
      {outbound ? "Out" : "In"}
    </span>
  );
}

/** One direction of an aggregate's traffic: arrow + bytes. */
export function TrafficValue({
  direction,
  counters,
}: {
  direction: "inbound" | "outbound";
  counters: Counters;
}) {
  const inbound = direction === "inbound";
  const Icon = inbound ? ArrowDown : ArrowUp;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-medium tabular-nums whitespace-nowrap",
        inbound ? "text-series-inbound" : "text-series-outbound",
      )}
      title={`${formatNumber(counters.packets)} packets ${inbound ? "inbound (entering ZimaOS)" : "outbound (leaving ZimaOS)"}`}
    >
      <Icon className="size-3" strokeWidth={2.2} />
      {formatBytes(counters.bytes)}
    </span>
  );
}

export function EvidenceChip({
  evidence,
  confidence,
}: {
  evidence: Evidence;
  confidence?: Confidence;
}) {
  return (
    <span
      title={evidenceTitle(evidence)}
      className="inline-flex items-center gap-1 rounded-full bg-secondary px-2 py-0.5 text-xs font-medium whitespace-nowrap text-secondary-foreground"
    >
      {evidenceLabel(evidence)}
      {confidence && (
        <em className="font-normal not-italic text-muted-foreground">
          {confidence === "direct" ? "direct" : "inferred"}
        </em>
      )}
    </span>
  );
}

function evidenceLabel(evidence: Evidence): string {
  switch (evidence) {
    case "dns":
      return "DNS";
    case "tls_sni":
      return "TLS SNI";
    case "http_host":
      return "HTTP Host";
  }
}

export function ScopeChip({ scope }: { scope: Scope }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border/70 px-2 py-0.5 text-xs whitespace-nowrap",
        scope === "fake_ip" ? "border-warning/40 text-warning" : "text-muted-foreground",
      )}
    >
      {scopeLabel(scope)}
    </span>
  );
}

export function CountryLabel({
  country,
  fallback = "—",
}: {
  country: string | null | undefined;
  fallback?: string;
}) {
  if (!country) return <span className="text-muted-foreground">{fallback}</span>;
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <span aria-hidden>{flagEmoji(country)}</span>
      {country}
    </span>
  );
}

export function StatusDot({
  state,
  className,
}: {
  state: "running" | "degraded" | "stopped";
  className?: string;
}) {
  return (
    <span
      className={cn(
        "size-2 shrink-0 rounded-full",
        state === "running" && "bg-success",
        state === "degraded" && "bg-warning",
        state === "stopped" && "bg-muted-foreground/50",
        className,
      )}
    />
  );
}
