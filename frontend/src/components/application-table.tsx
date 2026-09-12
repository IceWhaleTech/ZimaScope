/**
 * Application table row — one process or container and its boundary traffic.
 */

import { memo } from "react";
import { Boxes, Terminal } from "lucide-react";
import { TableCell, TableRow } from "@/components/ui/table";
import { TrafficValue } from "@/components/flow-bits";
import { relativeTime } from "@/lib/format";
import type { ApplicationSummary } from "@/types";

export const ApplicationRow = memo(function ApplicationRow({
  application,
  onOpen,
}: {
  application: ApplicationSummary;
  onOpen: (id: string) => void;
}) {
  const Icon = application.kind === "container" ? Boxes : Terminal;
  return (
    <TableRow
      tabIndex={0}
      className="cursor-pointer"
      data-menu="application"
      data-id={application.id}
      data-name={application.name}
      onClick={() => onOpen(application.id)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen(application.id);
        }
      }}
    >
      <TableCell>
        <span className="flex min-w-0 items-center gap-2">
          <Icon className="size-3.5 shrink-0 text-muted-foreground" />
          <span className="block min-w-0 truncate">
            <span className="block truncate font-medium" title={application.exe ?? application.id}>
              {application.name}
            </span>
            <span className="block truncate text-2xs text-muted-foreground">
              {application.kind === "container"
                ? `container${application.container_id ? ` · ${application.container_id.slice(0, 12)}` : ""}`
                : (application.exe ?? application.id)}
            </span>
          </span>
        </span>
      </TableCell>
      <TableCell>
        <TrafficValue direction="inbound" counters={application.traffic.inbound} />
      </TableCell>
      <TableCell>
        <TrafficValue direction="outbound" counters={application.traffic.outbound} />
      </TableCell>
      <TableCell>
        <span className="tabular-nums text-muted-foreground">{application.flow_count}</span>
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={`first seen ${relativeTime(application.first_seen)}`}>
          {relativeTime(application.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
});

export const APPLICATION_COLUMNS = [
  { label: "Application", sort: "name", width: "34%" },
  { label: "Inbound", sort: "in_bytes", width: "16%" },
  { label: "Outbound", sort: "out_bytes", width: "16%" },
  { label: "Flows", sort: "flows", width: "14%" },
  { label: "Last seen", sort: "last_seen", width: "20%" },
] as const;
