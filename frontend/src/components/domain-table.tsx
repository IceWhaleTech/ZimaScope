/**
 * Domain table row — single-line, essentials only. Flow count and
 * first-seen live in the detail panel or hover tooltips.
 */

import { memo } from "react";
import { TableCell, TableRow } from "@/components/ui/table";
import { ByteValues, EvidenceChip, RateValues } from "@/components/flow-bits";
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
      data-menu="domain"
      data-domain={domain.domain}
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
        <RateValues inbound={domain.inbound_bps} outbound={domain.outbound_bps} />
      </TableCell>
      <TableCell>
        <ByteValues inbound={domain.traffic.inbound} outbound={domain.traffic.outbound} />
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
  { label: "Domain", sort: "domain", width: "32%" },
  { label: "Evidence", sort: "evidence", width: "12%" },
  { label: "Rate", sort: "rate", sorts: ["rate", "in_rate", "out_rate"], width: "20%" },
  {
    label: "Total",
    sort: "bytes",
    sorts: ["bytes", "in_bytes", "out_bytes"],
    width: "17%",
  },
  { label: "Last seen", sort: "last_seen", width: "19%" },
] as const;
