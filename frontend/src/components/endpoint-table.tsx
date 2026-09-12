/**
 * Endpoint table row — single-line, essentials only. Scope, flow count,
 * packets and first-seen live in the detail panel or hover tooltips.
 */

import { memo } from "react";
import { TableCell, TableRow } from "@/components/ui/table";
import { CountryLabel, TrafficValue } from "@/components/flow-bits";
import { formatNumber, networkLabel, relativeTime, scopeLabel } from "@/lib/format";
import type { EndpointSummary } from "@/types";

export const EndpointRow = memo(function EndpointRow({
  endpoint,
  onOpen,
}: {
  endpoint: EndpointSummary;
  onOpen: (address: string) => void;
}) {
  return (
    <TableRow
      tabIndex={0}
      className="cursor-pointer"
      data-menu="endpoint"
      data-address={endpoint.address}
      onClick={() => onOpen(endpoint.address)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen(endpoint.address);
        }
      }}
    >
      <TableCell>
        <span
          className="block truncate font-mono text-[17px] font-medium"
          title={`${scopeLabel(endpoint.scope)}${endpoint.flow_count ? ` · ${formatNumber(endpoint.flow_count)} flows` : ""}`}
        >
          {endpoint.address}
        </span>
      </TableCell>
      <TableCell>
        {endpoint.country ? <CountryLabel country={endpoint.country} /> : <span className="text-muted-foreground">—</span>}
      </TableCell>
      <TableCell>
        <span className="block truncate" title={endpoint.organization ?? networkLabel(endpoint.scope, null)}>
          {networkLabel(endpoint.scope, endpoint.organization)}
          {endpoint.asn ? <span className="text-muted-foreground"> · AS{endpoint.asn}</span> : null}
        </span>
      </TableCell>
      <TableCell>
        <TrafficValue direction="inbound" counters={endpoint.traffic.inbound} />
      </TableCell>
      <TableCell>
        <TrafficValue direction="outbound" counters={endpoint.traffic.outbound} />
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={`first seen ${relativeTime(endpoint.first_seen)}`}>
          {relativeTime(endpoint.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
});

export const ENDPOINT_COLUMNS = [
  { label: "Address", sort: "address", width: "22%" },
  { label: "Region", sort: "country", width: "14%" },
  { label: "Network", sort: "organization", width: "26%" },
  { label: "Inbound", sort: "in_bytes", width: "13%" },
  { label: "Outbound", sort: "out_bytes", width: "13%" },
  { label: "Last seen", sort: "last_seen", width: "12%" },
] as const;
