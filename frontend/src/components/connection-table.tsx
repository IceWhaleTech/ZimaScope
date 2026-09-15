/**
 * Connection list: both directions of a Flow merged, then folded by
 * Associated Domain (or by peer when no domain is known). Group headers
 * aggregate the whole domain — one domain can span several peer addresses —
 * and expanding reveals the individual connections with their device-side
 * ports.
 */

import { memo } from "react";
import { Boxes, ChevronRight, Terminal } from "lucide-react";
import { TableCell, TableRow } from "@/components/ui/table";
import { ByteValues, EvidenceChip, FlowStateDot, RateValues } from "@/components/flow-bits";
import {
  flagEmoji,
  formatDuration,
  relativeTime,
  unattributedLabel,
  unattributedTitle,
} from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ApplicationRef, Connection, DirectionTotals, UnattributedReason } from "@/types";

function endpointLabel(endpoint: Connection["remote"]): string {
  return `${endpoint.address}${endpoint.port ? `:${endpoint.port}` : ""}`;
}

/**
 * Service chip: a fingerprint match gets a solid chip, unmatched traffic
 * keeps the honest TCP/UDP fallback.
 */
function ServiceBadge({
  service,
  protocol,
  durationMs,
}: {
  service: string | null;
  protocol: Connection["protocol"];
  durationMs: number;
}) {
  const transport = protocol.toUpperCase();
  const title = service
    ? `${service} · matched from the first payload fingerprint · ${transport} · ${formatDuration(durationMs)}`
    : `No fingerprint match · ${transport} · ${formatDuration(durationMs)}`;
  return (
    <span
      title={title}
      className={cn(
        "rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        service ? "bg-secondary text-secondary-foreground" : "text-muted-foreground/70",
      )}
    >
      {service ?? transport}
    </span>
  );
}

function DomainCell({ domains }: { domains: Connection["domains"] }) {
  const [first, ...rest] = domains;
  if (!first) {
    return (
      <span
        className="rounded-full border border-dashed border-border/70 px-2 py-0.5 text-2xs text-muted-foreground"
        title="No DNS answer, TLS SNI or HTTP Host was observed for this connection. DNS cache, DoH/ECH, QUIC or IP-only connections can hide it."
      >
        No domain
      </span>
    );
  }
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span className="truncate font-medium">{first.domain}</span>
      <EvidenceChip evidence={first.evidence} confidence={first.confidence} />
      {rest.length > 0 && (
        <span className="shrink-0 text-2xs text-muted-foreground" title={rest.map((ref) => ref.domain).join(", ")}>
          +{rest.length}
        </span>
      )}
    </span>
  );
}

/** Evidence chips for a domain group, deduplicated across peers. */
function EvidenceCell({ domains }: { domains: Connection["domains"] }) {
  const evidences = [...new Set(domains.map((ref) => ref.evidence))];
  if (!evidences.length) return <span className="text-muted-foreground">—</span>;
  return (
    <span className="flex items-center gap-1">
      {evidences.map((evidence) => (
        <EvidenceChip
          key={evidence}
          evidence={evidence}
          confidence={evidence === "dns" ? "inferred" : "direct"}
        />
      ))}
    </span>
  );
}

/** Application Identity of a row or group; clusters fold to `Name +N`. */
function ApplicationCell({
  applications,
  reason,
}: {
  applications: ApplicationRef[];
  reason?: UnattributedReason | null;
}) {
  const [first] = applications;
  if (!first) {
    return (
      <span className="text-muted-foreground italic" title={unattributedTitle(reason)}>
        {unattributedLabel(reason)}
      </span>
    );
  }
  const Icon = first.kind === "container" ? Boxes : Terminal;
  const title =
    applications.length === 1
      ? `${first.kind === "container" ? "Container" : "Process"} · ${first.id}`
      : applications.map((application) => application.id).join(", ");
  return (
    <span className="flex min-w-0 items-center gap-1.5" title={title}>
      <Icon className="size-3 shrink-0 text-muted-foreground" />
      <span className="truncate font-medium">{first.name}</span>
      {applications.length > 1 && (
        <span className="shrink-0 text-2xs text-muted-foreground">+{applications.length - 1}</span>
      )}
    </span>
  );
}

/// Numeric key for IPv4 so `2.2.2.2` sorts before `10.0.0.1`; anything else
/// sorts after IPv4 and falls back to the group-key tie-break.
function ipSortKey(address: string): number {
  const parts = address.split(".");
  if (parts.length !== 4) return Number.MAX_SAFE_INTEGER;
  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return Number.MAX_SAFE_INTEGER;
    value = value * 256 + octet;
  }
  return value;
}

/// RFC 4034 style key: labels from the root up, NUL-separated so a parent
/// domain sorts before its own subdomains (`example.com` < `api.example.com`).
function domainSortKey(domain: string): string {
  return domain.split(".").filter(Boolean).reverse().join("\u0000");
}

export interface ConnectionGroup {
  key: string;
  /** Domain groups fold by Associated Domain; peer groups have none. */
  kind: "domain" | "peer";
  label: string;
  service: string | null;
  remote: Connection["remote"];
  remote_profile: Connection["remote_profile"];
  /** Distinct remote endpoints inside the group. */
  peers: string[];
  connections: Connection[];
  bytes: number;
  packets: number;
  /** Sum of the latest-interval rates of the group's connections. */
  inbound_bps: number;
  outbound_bps: number;
  traffic: DirectionTotals;
  first_seen: number;
  last_seen: number;
  domains: Connection["domains"];
  /** Distinct Application Identities inside the group. */
  applications: ApplicationRef[];
  /** Every unattributed connection in the group is inbound LAN broadcast. */
  broadcast: boolean;
}

/**
 * Folds connections by domain first, then by peer address. A domain usually
 * spans several remote addresses (CDNs, proxy fake IPs) and a LAN client
 * spawns many ephemeral ports, so both levels would otherwise fragment the
 * totals; individual endpoints stay available on expand.
 */
export function groupConnections(connections: Connection[], sort: string): ConnectionGroup[] {
  const groups = new Map<string, ConnectionGroup>();
  for (const connection of connections) {
    const domain = connection.domains[0]?.domain;
    const serviceKey = connection.service ?? connection.protocol;
    const key = domain
      ? `domain:${domain}|${serviceKey}`
      : `peer:${connection.remote.address}|${serviceKey}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        key,
        kind: domain ? "domain" : "peer",
        label: domain ?? connection.remote.address,
        service: connection.service,
        remote: connection.remote,
        remote_profile: connection.remote_profile,
        peers: [],
        connections: [],
        bytes: 0,
        packets: 0,
        inbound_bps: 0,
        outbound_bps: 0,
        traffic: {
          inbound: { packets: 0, bytes: 0 },
          outbound: { packets: 0, bytes: 0 },
        },
        first_seen: connection.first_seen,
        last_seen: connection.last_seen,
        domains: [],
        applications: [],
        broadcast: true,
      };
      groups.set(key, group);
    }
    const peer = `${connection.remote.address}:${connection.remote.port ?? -1}`;
    if (!group.peers.includes(peer)) group.peers.push(peer);
    group.connections.push(connection);
    group.bytes += connection.bytes;
    group.packets += connection.packets;
    group.inbound_bps += connection.inbound_bps;
    group.outbound_bps += connection.outbound_bps;
    group.traffic.inbound.packets += connection.traffic.inbound.packets;
    group.traffic.inbound.bytes += connection.traffic.inbound.bytes;
    group.traffic.outbound.packets += connection.traffic.outbound.packets;
    group.traffic.outbound.bytes += connection.traffic.outbound.bytes;
    group.first_seen = Math.min(group.first_seen, connection.first_seen);
    group.last_seen = Math.max(group.last_seen, connection.last_seen);
    for (const ref of connection.domains) {
      if (!group.domains.some((existing) => existing.domain === ref.domain)) {
        group.domains.push(ref);
      }
    }
    if (
      connection.application &&
      !group.applications.some((application) => application.id === connection.application!.id)
    ) {
      group.applications.push(connection.application);
    }
    group.broadcast =
      group.broadcast && connection.unattributed_reason === "lan_broadcast";
  }

  const field = sort.startsWith("-") ? sort.slice(1) : sort;
  const descending = sort.startsWith("-");
  // Groups must be ordered by the same field the header asked for; string
  // fields use the same orderings the server applies (numeric IPs, DNS
  // hierarchy) so a re-grouped page keeps the requested order.
  const value = (group: ConnectionGroup): number | string => {
    switch (field) {
      case "bytes":
        return group.bytes;
      case "packets":
        return group.packets;
      case "in_bytes":
        return group.traffic.inbound.bytes;
      case "out_bytes":
        return group.traffic.outbound.bytes;
      case "in_packets":
        return group.traffic.inbound.packets;
      case "out_packets":
        return group.traffic.outbound.packets;
      case "rate":
        return group.inbound_bps + group.outbound_bps;
      case "in_rate":
        return group.inbound_bps;
      case "out_rate":
        return group.outbound_bps;
      case "duration_ms":
        return Math.max(0, ...group.connections.map((connection) => connection.duration_ms));
      case "first_seen":
        return group.first_seen;
      case "service":
        return (group.service ?? group.connections[0].protocol).toLowerCase();
      case "remote":
        return ipSortKey(group.remote.address);
      case "domain":
        return domainSortKey(group.domains[0]?.domain ?? "");
      default:
        return group.last_seen;
    }
  };
  const items = [...groups.values()];
  items.sort((left, right) => {
    const leftValue = value(left);
    const rightValue = value(right);
    const order =
      typeof leftValue === "string" || typeof rightValue === "string"
        ? String(leftValue).localeCompare(String(rightValue))
        : leftValue - rightValue;
    if (order !== 0) return descending ? -order : order;
    // Deterministic tie-break so live refreshes do not reshuffle equal rows.
    return left.key.localeCompare(right.key);
  });
  return items;
}

const ConnectionRow = memo(function ConnectionRow({
  connection,
  onOpen,
}: {
  connection: Connection;
  onOpen?: (remoteAddress: string) => void;
}) {
  return (
    <TableRow
      data-connection-id={connection.id}
      data-menu="connection"
      data-address={connection.remote.address}
      data-port={connection.remote.port ?? undefined}
      data-domain={connection.domains[0]?.domain}
      tabIndex={0}
      className="cursor-pointer"
      onClick={() => onOpen?.(connection.remote.address)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen?.(connection.remote.address);
        }
      }}
    >
      <TableCell>
        <span className="flex items-center gap-1.5">
          <FlowStateDot state={connection.state} />
          <ServiceBadge
            service={connection.service}
            protocol={connection.protocol}
            durationMs={connection.duration_ms}
          />
        </span>
      </TableCell>
      <TableCell>
        <span
          className="flex items-center gap-1.5"
          title={`This device: ${endpointLabel(connection.host)}${connection.interface ? ` · ${connection.interface}` : ""}`}
        >
          {connection.remote_profile.country && (
            <span aria-hidden className="shrink-0 text-xs">
              {flagEmoji(connection.remote_profile.country)}
            </span>
          )}
          <span className="block truncate font-mono text-[17px] font-medium">
            {endpointLabel(connection.remote)}
          </span>
        </span>
      </TableCell>
      <TableCell>
        <ApplicationCell
          applications={connection.application ? [connection.application] : []}
          reason={connection.unattributed_reason}
        />
      </TableCell>
      <TableCell>
        <DomainCell domains={connection.domains} />
      </TableCell>
      <TableCell>
        <RateValues inbound={connection.inbound_bps} outbound={connection.outbound_bps} />
      </TableCell>
      <TableCell>
        <ByteValues inbound={connection.traffic.inbound} outbound={connection.traffic.outbound} />
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={`started ${relativeTime(connection.first_seen)}`}>
          {relativeTime(connection.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
});

function GroupRow({
  group,
  expanded,
  onToggle,
}: {
  group: ConnectionGroup;
  expanded: boolean;
  onToggle: () => void;
}) {
  const domainGroup = group.kind === "domain";
  return (
    <TableRow
      tabIndex={0}
      className="cursor-pointer bg-muted/40 hover:bg-accent"
      aria-expanded={expanded}
      data-menu={domainGroup ? "domain" : "endpoint"}
      data-domain={domainGroup ? (group.domains[0]?.domain ?? group.label) : undefined}
      data-address={domainGroup ? undefined : group.remote.address}
      onClick={onToggle}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onToggle();
        }
      }}
    >
      <TableCell>
        <span className="flex items-center gap-1.5">
          <ChevronRight
            className={cn("size-3.5 shrink-0 text-muted-foreground transition-transform", expanded && "rotate-90")}
          />
          <ServiceBadge
            service={group.service}
            protocol={group.connections[0].protocol}
            durationMs={group.last_seen - group.first_seen}
          />
        </span>
      </TableCell>
      <TableCell>
        {domainGroup ? (
          <span
            className="flex min-w-0 items-center gap-1.5"
            title={`${group.peers.length} peer${group.peers.length === 1 ? "" : "s"}: ${group.peers.join(", ")}`}
          >
            <span className="truncate font-medium">{group.label}</span>
            <span className="shrink-0 rounded-full bg-secondary px-1.5 py-px text-2xs text-secondary-foreground">
              {group.connections.length} connections · {group.peers.length} peers
            </span>
          </span>
        ) : (
          <span
            className="flex min-w-0 items-center gap-1.5"
            title={`${group.peers.length} endpoint${group.peers.length === 1 ? "" : "s"}: ${group.peers.join(", ")}`}
          >
            {group.remote_profile.country && (
              <span aria-hidden className="shrink-0 text-xs">
                {flagEmoji(group.remote_profile.country)}
              </span>
            )}
            <span className="truncate font-mono text-[17px] font-medium">{group.label}</span>
            <span className="shrink-0 rounded-full bg-secondary px-1.5 py-px text-2xs text-secondary-foreground">
              {group.connections.length} connections
            </span>
          </span>
        )}
      </TableCell>
      <TableCell>
        <ApplicationCell
          applications={group.applications}
          reason={group.broadcast ? "lan_broadcast" : null}
        />
      </TableCell>
      <TableCell>
        {domainGroup ? <EvidenceCell domains={group.domains} /> : <DomainCell domains={group.domains} />}
      </TableCell>
      <TableCell>
        <RateValues inbound={group.inbound_bps} outbound={group.outbound_bps} />
      </TableCell>
      <TableCell>
        <ByteValues inbound={group.traffic.inbound} outbound={group.traffic.outbound} />
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={`first ${relativeTime(group.first_seen)}`}>
          {relativeTime(group.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
}

const ChildRow = memo(function ChildRow({
  connection,
  kind,
  onOpen,
}: {
  connection: Connection;
  /** Domain groups hide the peer on the parent; peer groups hide the ports. */
  kind: ConnectionGroup["kind"];
  onOpen?: (remoteAddress: string) => void;
}) {
  return (
    <TableRow
      data-connection-id={connection.id}
      data-menu="connection"
      data-address={connection.remote.address}
      data-port={connection.remote.port ?? undefined}
      data-domain={connection.domains[0]?.domain}
      tabIndex={0}
      className="cursor-pointer bg-muted/10 hover:bg-accent"
      onClick={() => onOpen?.(connection.remote.address)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen?.(connection.remote.address);
        }
      }}
    >
      <TableCell className="pl-8">
        <span className="flex items-center gap-1.5">
          <FlowStateDot state={connection.state} />
          <span
            className="text-2xs text-muted-foreground"
            title={`duration ${formatDuration(connection.duration_ms)}`}
          >
            {connection.duration_ms >= 60_000 ? formatDuration(connection.duration_ms) : "<1m"}
          </span>
        </span>
      </TableCell>
      <TableCell>
        {kind === "domain" ? (
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="truncate font-mono text-xs">{endpointLabel(connection.remote)}</span>
            <span
              className="shrink-0 font-mono text-2xs text-muted-foreground"
              title={`This device: ${endpointLabel(connection.host)}`}
            >
              :{connection.host.port ?? "—"}
            </span>
          </span>
        ) : (
          <span
            className="flex items-center gap-1 font-mono text-xs text-muted-foreground"
            title={`${endpointLabel(connection.remote)} → ${endpointLabel(connection.host)}`}
          >
            <span>{connection.remote.port ? `:${connection.remote.port}` : "—"}</span>
            <span aria-hidden>→</span>
            <span title="This device side">:{connection.host.port ?? "—"}</span>
          </span>
        )}
      </TableCell>
      <TableCell>
        <ApplicationCell
          applications={connection.application ? [connection.application] : []}
          reason={connection.unattributed_reason}
        />
      </TableCell>
      <TableCell>
        <DomainCell domains={connection.domains} />
      </TableCell>
      <TableCell>
        <RateValues inbound={connection.inbound_bps} outbound={connection.outbound_bps} />
      </TableCell>
      <TableCell>
        <ByteValues inbound={connection.traffic.inbound} outbound={connection.traffic.outbound} />
      </TableCell>
      <TableCell>
        <span className="whitespace-nowrap" title={`started ${relativeTime(connection.first_seen)}`}>
          {relativeTime(connection.last_seen)}
        </span>
      </TableCell>
    </TableRow>
  );
});

/**
 * Renders grouped connections: singleton groups stay flat rows, larger groups
 * fold behind a header.
 */
/** Flattened render list for the windowed connections table. */
export type ConnectionListItem =
  | { type: "single"; connection: Connection }
  | { type: "group"; group: ConnectionGroup; expanded: boolean }
  | { type: "child"; connection: Connection; kind: ConnectionGroup["kind"] };

/**
 * Folds grouped connections into a flat list the table can window: single
 * connections stay one row, multi-connection groups emit their header and —
 * only while expanded — their child rows.
 */
export function flattenConnectionGroups(
  groups: ConnectionGroup[],
  expandedKeys: Set<string>,
): ConnectionListItem[] {
  const items: ConnectionListItem[] = [];
  for (const group of groups) {
    if (group.connections.length === 1) {
      items.push({ type: "single", connection: group.connections[0] });
      continue;
    }
    const expanded = expandedKeys.has(group.key);
    items.push({ type: "group", group, expanded });
    if (expanded) {
      for (const connection of group.connections) {
        items.push({ type: "child", connection, kind: group.kind });
      }
    }
  }
  return items;
}

export function ConnectionRows({
  items,
  onToggle,
  onOpen,
}: {
  items: ConnectionListItem[];
  onToggle: (key: string) => void;
  onOpen: (remoteAddress: string) => void;
}) {
  return (
    <>
      {items.map((item) => {
        if (item.type === "single") {
          return <ConnectionRow key={item.connection.id} connection={item.connection} onOpen={onOpen} />;
        }
        if (item.type === "group") {
          return (
            <GroupRow
              key={item.group.key}
              group={item.group}
              expanded={item.expanded}
              onToggle={() => onToggle(item.group.key)}
            />
          );
        }
        return <ChildRow key={item.connection.id} connection={item.connection} kind={item.kind} onOpen={onOpen} />;
      })}
    </>
  );
}

export const CONNECTION_COLUMNS = [
  { label: "Service", sort: "service", width: "9%" },
  { label: "Remote endpoint", sort: "remote", width: "21%" },
  { label: "Application", sort: "application", width: "13%" },
  { label: "Associated domain", sort: "domain", width: "20%" },
  { label: "Rate", sort: "rate", sorts: ["rate", "in_rate", "out_rate"], width: "15%" },
  {
    label: "Total",
    sort: "bytes",
    sorts: ["bytes", "in_bytes", "out_bytes"],
    width: "12%",
  },
  { label: "Last seen", sort: "last_seen", width: "10%" },
] as const;
