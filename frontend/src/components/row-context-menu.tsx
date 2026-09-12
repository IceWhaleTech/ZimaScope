/**
 * Right-click actions for Explorer rows. Radix's per-row trigger injects an
 * anchor node into <tbody>, which breaks the zebra striping's :nth-child
 * parity — so the table surface owns a single menu and resolves the row under
 * the cursor from `data-menu` attributes. Details, filters and copies act on
 * the local API; rate limiting and blocking create Traffic Rules through the
 * dialog. Domain rows cannot become rules because domain matching is not
 * supported, and the menu says so instead of pretending.
 */

import { useState, type ReactElement } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";
import { ArrowLeftRight, Ban, Copy, Eye, Gauge, Globe } from "lucide-react";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuLabel,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import { TrafficRuleDialog, type TrafficRulePreset } from "@/components/traffic-rule-dialog";
import { useDetails } from "@/hooks/use-details";
import { cn } from "@/lib/utils";
import type { RuleAction } from "@/types";

/** What a right-clicked row stands for; rows advertise it via data attributes. */
type RowMenuTarget =
  | { kind: "connection"; address: string; domain: string | null; port: number | null }
  | { kind: "endpoint"; address: string }
  | { kind: "domain"; domain: string }
  | { kind: "application"; id: string; name: string };

interface RowMenuCopy {
  value: string;
  label: string;
  /** Menu wording for the generic copy item; omitted by the domain shortcut. */
  menu?: string;
}

function resolveTarget(node: EventTarget | null): RowMenuTarget | null {
  if (!(node instanceof Element)) return null;
  const row = node.closest<HTMLElement>("[data-menu]");
  if (!row) return null;
  const { menu, address, domain, id, name, port } = row.dataset;
  if (menu === "connection" && address) {
    const parsedPort = port ? Number(port) : Number.NaN;
    return {
      kind: "connection",
      address,
      domain: domain || null,
      port: Number.isFinite(parsedPort) ? parsedPort : null,
    };
  }
  if (menu === "endpoint" && address) return { kind: "endpoint", address };
  if (menu === "domain" && domain) return { kind: "domain", domain };
  if (menu === "application" && id) return { kind: "application", id, name: name || id };
  return null;
}

function targetLabel(target: RowMenuTarget): string {
  return target.kind === "application" ? target.name : target.kind === "domain" ? target.domain : target.address;
}

function filterLabel(target: RowMenuTarget): string {
  if (target.kind === "domain") return "Filter flows by this domain";
  if (target.kind === "application") return "Filter flows by this application";
  return "Filter flows by this endpoint";
}

function copyTarget(target: RowMenuTarget): RowMenuCopy {
  if (target.kind === "domain") {
    return { value: target.domain, label: "Domain", menu: "Copy domain" };
  }
  if (target.kind === "application") {
    return { value: target.id, label: "Application ID", menu: "Copy application ID" };
  }
  return { value: target.address, label: "Endpoint address", menu: "Copy endpoint address" };
}

export function RowContextMenu({ children }: { children: ReactElement }) {
  const [target, setTarget] = useState<RowMenuTarget | null>(null);
  const [preset, setPreset] = useState<TrafficRulePreset | null>(null);
  const { open } = useDetails();
  const navigate = useNavigate();
  const domain = target?.kind === "connection" ? target.domain : null;

  const showDetails = (row: RowMenuTarget) => {
    if (row.kind === "domain") open({ kind: "domain", name: row.domain });
    else if (row.kind === "application") open({ kind: "application", id: row.id });
    else open({ kind: "endpoint", address: row.address });
  };

  const filterFlows = (row: RowMenuTarget) => {
    if (row.kind === "domain") navigate(`/flows?domain=${encodeURIComponent(row.domain)}`);
    else if (row.kind === "application") navigate(`/flows?application=${encodeURIComponent(row.id)}`);
    else navigate(`/flows?ip=${encodeURIComponent(row.address)}`);
  };

  const copy = ({ value, label }: RowMenuCopy) => {
    if (!navigator.clipboard) {
      toast.error("Clipboard is unavailable on this connection");
      return;
    }
    void navigator.clipboard.writeText(value).then(
      () => toast.success(`${label} copied`),
      () => toast.error("Could not write to the clipboard"),
    );
  };

  const openRuleDialog = (row: RowMenuTarget, action: RuleAction) => {
    if (row.kind === "application") {
      setPreset({
        action,
        label: row.name,
        selector: { kind: "application", id: row.id },
      });
      return;
    }
    if (row.kind === "connection") {
      setPreset({
        action,
        label: row.address,
        selector: {
          kind: "endpoint",
          address: row.address,
          port: row.port ?? undefined,
        },
      });
      return;
    }
    if (row.kind === "endpoint") {
      setPreset({
        action,
        label: row.address,
        selector: { kind: "endpoint", address: row.address },
      });
    }
  };

  return (
    <ContextMenu>
      <ContextMenuTrigger
        asChild
        onContextMenu={(event) => {
          const next = resolveTarget(event.target);
          setTarget(next);
          // Radix opens on this same event; when the press missed every row,
          // the default is prevented so neither the native menu nor a
          // row-less Radix menu appears.
          if (!next) event.preventDefault();
        }}
      >
        {children}
      </ContextMenuTrigger>
      <ContextMenuContent className="w-60">
        {target && (
          <>
            <ContextMenuLabel
              className={cn(
                "truncate text-2xs font-medium text-muted-foreground",
                target.kind !== "application" && "font-mono",
              )}
            >
              {targetLabel(target)}
            </ContextMenuLabel>
            <ContextMenuSeparator />
            <ContextMenuItem onSelect={() => showDetails(target)}>
              <Eye />
              View details
            </ContextMenuItem>
            <ContextMenuItem onSelect={() => filterFlows(target)}>
              <ArrowLeftRight />
              {filterLabel(target)}
            </ContextMenuItem>
            {domain && (
              <ContextMenuItem onSelect={() => filterFlows({ kind: "domain", domain })}>
                <Globe />
                Filter flows by this domain
              </ContextMenuItem>
            )}
            <ContextMenuItem onSelect={() => copy(copyTarget(target))}>
              <Copy />
              {copyTarget(target).menu}
            </ContextMenuItem>
            {domain && (
              <ContextMenuItem onSelect={() => copy({ value: domain, label: "Domain" })}>
                <Copy />
                Copy domain
              </ContextMenuItem>
            )}
            <ContextMenuSeparator />
            {target.kind === "domain" ? (
              <ContextMenuItem disabled>
                <Gauge />
                Rate limiting is not available for domains
              </ContextMenuItem>
            ) : (
              <>
                <ContextMenuItem onSelect={() => openRuleDialog(target, "limit")}>
                  <Gauge />
                  Rate limit
                </ContextMenuItem>
                <ContextMenuItem
                  variant="destructive"
                  onSelect={() => openRuleDialog(target, "block")}
                >
                  <Ban />
                  Block traffic
                </ContextMenuItem>
              </>
            )}
          </>
        )}
      </ContextMenuContent>
      <TrafficRuleDialog preset={preset} onClose={() => setPreset(null)} />
    </ContextMenu>
  );
}
