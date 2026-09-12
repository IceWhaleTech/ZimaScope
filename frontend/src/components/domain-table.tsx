/**
 * Domain table row — single-line, essentials only. Flow count and
 * first-seen live in the detail panel or hover tooltips.
 */

import { memo } from "react";
import { TableCell, TableRow } from "@/components/ui/table";
import { EvidenceChip, TrafficValue } from "@/components/flow-bits";
import { relativeTime } from "@/lib/format";
import type { DomainSummary } from "@/types";

export const DomainRow = memo(function DomainRow({
  domain,
  onOpen,
}: {
  domain: DomainSummary;
  onOpen: (name: string) => void;
}) {
  return (
    <TableRow
      tabIndex={0}
      className="cursor-pointer"
      onClick={() => onOpen(domain.domain)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen(domain.domain);
        }
      }}
    >
      <TableCell>
        <span className="block truncate font-medium" title={domain.domain}>
          {domain.domain}
        </span>
      </TableCell>
      <TableCell>
        <span className="flex items-center gap-1">
          {domain.evidence.map((evidence) => (
            <EvidenceChip
              key={evidence}
              evidence={evidence}
              confidence={evidence === "dns" ? "inferred" : "direct"}
            />
          ))}
        </span>
      </TableCell>
      <TableCell>
        <TrafficValue direction="inbound" counters={domain.traffic.inbound} />
      </TableCell>
      <TableCell>
        <TrafficValue direction="outbound" counters={domain.traffic.outbound} />
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={`first seen ${relativeTime(domain.first_seen)}`}>
          {relativeTime(domain.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
});

export const DOMAIN_COLUMNS = [
  { label: "Domain", sort: "domain", width: "30%" },
  { label: "Evidence", sort: "evidence", width: "16%" },
  { label: "Inbound", sort: "in_bytes", width: "18%" },
  { label: "Outbound", sort: "out_bytes", width: "18%" },
  { label: "Last seen", sort: "last_seen", width: "18%" },
] as const;
