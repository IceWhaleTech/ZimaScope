/**
 * The flow table row shared by Overview (recent flows) and Flows (the full
 * ledger). Rows stay single-line and show only the essentials; everything
 * else (protocol, interface, network profile, packets, duration, state
 * detail) is one click away in the detail panel or a hover tooltip away.
 * The blind-spot state stays honest: "Domain unavailable" with the reason
 * on hover, full explanation in the detail panel.
 */

import { memo } from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import { TableCell, TableRow } from "@/components/ui/table";
import { DirectionBadge, EvidenceChip, FlowStateDot } from "@/components/flow-bits";
import { flagEmoji, formatBytes, formatDuration, formatNumber, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Flow } from "@/types";

export const FlowRow = memo(function FlowRow({
  flow,
  selected,
  onOpen,
}: {
  flow: Flow;
  selected?: boolean;
  onOpen?: (id: string) => void;
}) {
  const domain = flow.domains[0];
  return (
    <TableRow
      data-flow-id={flow.id}
      tabIndex={0}
      aria-selected={selected || undefined}
      className={cn("cursor-pointer", selected && "bg-accent")}
      onClick={() => onOpen?.(flow.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen?.(flow.id);
        }
      }}
    >
      <TableCell>
        <span className="flex items-center gap-1.5">
          <FlowStateDot state={flow.state} />
          <DirectionBadge direction={flow.direction} />
        </span>
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-1.5">
          {flow.remote_profile.country && (
            <span
              aria-hidden
              className="shrink-0 text-xs"
              title={flow.remote_profile.organization ?? flow.remote_profile.country}
            >
              {flagEmoji(flow.remote_profile.country)}
            </span>
          )}
          <span
            className="block truncate font-mono text-[17px] font-medium"
            title={`${flow.protocol.toUpperCase()}${flow.interface ? ` · ${flow.interface}` : ""}`}
          >
            {flow.remote.address}
            {flow.remote.port ? `:${flow.remote.port}` : ""}
          </span>
        </span>
      </TableCell>
      <TableCell>
        {domain ? (
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="truncate font-medium">{domain.domain}</span>
            <EvidenceChip evidence={domain.evidence} confidence={domain.confidence} />
          </span>
        ) : (
          <span className="text-muted-foreground italic" title="DNS/SNI not observed">
            Domain unavailable
          </span>
        )}
      </TableCell>
      <TableCell>
        <span
          className={cn(
            "inline-flex items-center gap-1 font-medium tabular-nums",
            flow.direction === "inbound" ? "text-series-inbound" : "text-series-outbound",
          )}
          title={`${formatNumber(flow.packets)} packets ${flow.direction === "inbound" ? "inbound (entering ZimaOS)" : "outbound (leaving ZimaOS)"}`}
        >
          {flow.direction === "inbound" ? (
            <ArrowDown className="size-3" strokeWidth={2.2} />
          ) : (
            <ArrowUp className="size-3" strokeWidth={2.2} />
          )}
          {formatBytes(flow.bytes)}
        </span>
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={formatDuration(flow.duration_ms)}>
          {relativeTime(flow.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
});

export const FLOW_COLUMNS = [
  { label: "Direction", sort: "direction", width: "10%" },
  { label: "Remote endpoint", sort: "remote", width: "30%" },
  { label: "Associated domain", sort: "domain", width: "28%" },
  { label: "Traffic", sort: "bytes", width: "16%" },
  { label: "Last seen", sort: "last_seen", width: "16%" },
] as const;
