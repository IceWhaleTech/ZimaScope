/**
 * Settings — grouped controls in the spirit of System Settings: one flat
 * section per intent, switches for booleans, segmented controls for small
 * choices, and a destructive action kept clearly apart.
 */

import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { FileDown, FileText, Loader2, Lock, Trash2, TriangleAlert, Wifi } from "lucide-react";
import { toast } from "sonner";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { ExportTasks } from "@/components/export-tasks";
import { Segmented } from "@/components/segmented";
import { DefList } from "@/components/stat-tiles";
import {
  useClearHistory,
  useCreateExport,
  useDeleteTrafficRule,
  useInterfaces,
  useSaveSettings,
  useSettings,
  useStatus,
  useTrafficRules,
  useUpdateTrafficRule,
} from "@/hooks/use-data";
import { useSetTopbar } from "@/hooks/use-topbar";
import { downloadExport } from "@/lib/download";
import { directionLabel, formatDuration, formatNumber, formatRateText, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type {
  InterfaceInfo,
  InterfaceKind,
  ProxySettings,
  SettingsPatch,
  TrafficRule,
} from "@/types";

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : "The local agent did not respond.";
}

export function SettingsView() {
  useSetTopbar("Settings", "Local-first controls");
  const settingsQuery = useSettings();
  const statusQuery = useStatus();
  const saveSettings = useSaveSettings();
  const clearHistory = useClearHistory();
  const createExport = useCreateExport();
  const settings = settingsQuery.data;
  const status = statusQuery.data;
  const queryClient = useQueryClient();

  const persist = (patch: SettingsPatch, message = "Settings saved") =>
    saveSettings.mutate(patch, {
      onSuccess: () => {
        toast.success(message);
        // The catalog's warnings are computed against the stored boundary.
        void queryClient.invalidateQueries({ queryKey: ["interfaces"] });
      },
    });

  const runExport = (format: "json" | "csv") =>
    createExport.mutate(
      { format },
      {
        onSuccess: (task) => {
          toast.success(`Export ready · ${formatNumber(task.record_count)} records`, {
            description: task.truncated ? "Only the first 10,000 records are included." : undefined,
            action: { label: "Download", onClick: () => downloadExport(task.id) },
          });
        },
      },
    );

  const unreachable = settingsQuery.isError || statusQuery.isError;

  return (
    <div className="grid items-start gap-x-12 gap-y-8 lg:grid-cols-2">
      {unreachable && (
        <div className="flex items-start gap-2.5 rounded-lg border border-destructive/30 bg-destructive/8 px-3.5 py-2.5 lg:col-span-2">
          <TriangleAlert className="mt-px size-4 shrink-0 text-destructive" />
          <div className="min-w-0">
            <strong className="block text-xs font-medium text-destructive">Agent unavailable</strong>
            <p className="mt-0.5 text-2xs leading-relaxed break-words text-muted-foreground">
              {errorText(settingsQuery.error ?? statusQuery.error)}
            </p>
          </div>
        </div>
      )}
      <CollectionCard
        settings={settings}
        status={status}
        saving={saveSettings.isPending}
        onEnabled={(checked) => persist({ enabled: checked }, checked ? "Collection enabled" : "Collection paused")}
      />

      <BoundaryCard
        settings={settings}
        saving={saveSettings.isPending}
        onSave={(interfaces) =>
          persist(
            { boundary: { interfaces } },
            interfaces.length ? "Device boundary updated" : "Boundary follows the default route",
          )
        }
      />

      <DomainCard
        settings={settings}
        saving={saveSettings.isPending}
        onDomainsEnabled={(checked) => persist({ domains: { enabled: checked } }, checked ? "Domain observation on" : "Domain observation off")}
        onDns={(checked) => persist({ domains: { dns: checked } })}
        onSni={(checked) => persist({ domains: { tls_sni: checked } })}
        onHost={(checked) => persist({ domains: { http_host: checked } })}
      />

      <HistoryCard
        settings={settings}
        saving={saveSettings.isPending}
        onHistoryEnabled={(checked) => persist({ history: { enabled: checked } }, checked ? "History on" : "History off")}
        onRetention={(days) => persist({ history: { enabled: true, retention_days: days } }, `Retention set to ${days} days`)}
      />

      <ResourcesCard
        settings={settings}
        saving={saveSettings.isPending}
        onMaxFlowEntries={(value) => persist({ resources: { max_flow_entries: value } })}
        onDiskQuota={(value) => persist({ resources: { disk_quota_mb: value } })}
      />

      <ProxyCard
        settings={settings}
        status={status}
        saving={saveSettings.isPending}
        onPatch={(patch) => persist({ proxy: patch })}
      />

      <TrafficRulesCard
        settings={settings}
        status={status}
        saving={saveSettings.isPending}
        onMasterEnabled={(checked) =>
          persist(
            { traffic_rules: { enabled: checked } },
            checked ? "Enforcement on" : "Enforcement paused",
          )
        }
      />

      <DataCard
        onExport={(format) => void runExport(format)}
        onClear={() =>
          clearHistory.mutate(undefined, { onSuccess: () => toast.success("Retained history cleared") })
        }
        clearing={clearHistory.isPending}
      />

      <AboutCard status={status} />
    </div>
  );
}

type SettingsData = NonNullable<ReturnType<typeof useSettings>["data"]>;
type StatusData = NonNullable<ReturnType<typeof useStatus>["data"]>;

function SettingsCard({
  title,
  description,
  children,
  className,
}: {
  title: string;
  description: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("flex flex-col", className)}>
      <div className="mb-2">
        <h2 className="text-sm font-semibold tracking-[0.01em]">{title}</h2>
        <p className="mt-0.5 text-2xs text-muted-foreground">{description}</p>
      </div>
      {children}
    </section>
  );
}

function SettingRow({
  title,
  detail,
  control,
  sub,
  column,
  disabled,
  last,
}: {
  title: string;
  detail: string;
  control?: React.ReactNode;
  sub?: boolean;
  column?: boolean;
  disabled?: boolean;
  last?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex gap-4 py-2.5",
        column ? "flex-col" : "items-center justify-between",
        sub && "pl-4",
        disabled && "pointer-events-none opacity-45",
        !last && "border-b border-border/60",
      )}
    >
      <div className={column ? "" : "min-w-0"}>
        <strong className="block text-xs font-medium">{title}</strong>
        <small className="mt-0.5 block text-2xs leading-relaxed text-muted-foreground">{detail}</small>
      </div>
      {control}
    </div>
  );
}

function CollectionCard({
  settings,
  status,
  saving,
  onEnabled,
}: {
  settings: SettingsData | undefined;
  status: StatusData | undefined;
  saving: boolean;
  onEnabled: (checked: boolean) => void;
}) {
  const health = status?.collector ?? null;
  return (
    <SettingsCard title="Collection" description="Whether ZimaScope observes the device boundary.">
      <SettingRow
        title="Enable ZimaScope"
        detail="Pausing stops collection; retained history stays available."
        control={
          settings ? (
            <Switch checked={settings.enabled} disabled={saving} onCheckedChange={onEnabled} />
          ) : (
            <Skeleton className="h-[26px] w-11 rounded-full" />
          )
        }
      />
      <SettingRow
        column
        last
        title="Collector status"
        detail="Attach state, map occupancy and observation gaps."
        control={
          status ? (
            <DefList
              compact
              rows={[
                { label: "Service", value: `${status.service} · v${status.version}` },
                { label: "Uptime", value: formatDuration(status.uptime_seconds * 1000) },
                {
                  label: "Interfaces",
                  wrap: true,
                  value:
                    health?.interfaces
                      .map(
                        (entry) =>
                          `${entry.name} ${entry.ingress_attached && entry.egress_attached ? "ingress + egress" : "partially attached"}`,
                      )
                      .join(", ") || "—",
                },
                {
                  label: "Map usage",
                  value: health ? `${formatNumber(health.map.entries)} / ${formatNumber(health.map.capacity)}` : "—",
                },
                { label: "Observation gaps", value: health?.gaps.length ? `${health.gaps.length} recorded` : "None" },
              ]}
            />
          ) : (
            <div className="flex flex-col gap-2 py-1">
              {Array.from({ length: 3 }, (_, index) => (
                <Skeleton key={index} className="h-6" />
              ))}
            </div>
          )
        }
      />
    </SettingsCard>
  );
}

const INTERFACE_KIND_LABELS: Record<InterfaceKind, string> = {
  loopback: "loopback",
  physical: "physical",
  bridge: "bridge",
  docker_bridge: "docker",
  bond: "bond",
  vlan: "vlan",
  tun_tap: "tun/tap",
  wireguard: "wireguard",
  veth: "veth",
  virtual: "virtual",
  other: "",
};

function interfaceState(info: InterfaceInfo): string {
  if (info.attached) return "attached";
  if (info.ingress_attached || info.egress_attached) return "partially attached";
  return info.up ? "up" : "down";
}

/** Device Boundary picker: choose the interfaces whose traffic is observed. */
function BoundaryCard({
  settings,
  saving,
  onSave,
}: {
  settings: SettingsData | undefined;
  saving: boolean;
  onSave: (interfaces: string[]) => void;
}) {
  const catalogQuery = useInterfaces();
  const catalog = catalogQuery.data;
  const selected = settings?.boundary.interfaces ?? [];
  const toggle = (name: string) => {
    const next = selected.includes(name)
      ? selected.filter((existing) => existing !== name)
      : [...selected, name];
    onSave(next);
  };

  return (
    <SettingsCard
      title="Device boundary"
      description="Interfaces where traffic enters or leaves this ZimaOS device. Direction is always relative to this boundary."
    >
      <SettingRow
        column
        title="Observed interfaces"
        detail="Leave every checkbox empty to follow the default route automatically. docker0, bridges and VPN tunnels attach when they appear."
        control={
          catalog ? (
            <div className="grid gap-1.5">
              <label className="flex items-center gap-2 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  className="size-3.5 accent-primary"
                  checked={selected.length === 0}
                  disabled={saving}
                  onChange={() => onSave([])}
                />
                Automatic · follow the default route
              </label>
              {catalog.interfaces.map((info) => (
                <label
                  key={info.name}
                  className={cn(
                    "flex items-center justify-between gap-2 rounded-md border px-2.5 py-1.5 text-xs",
                    selected.includes(info.name) && "border-primary/40 bg-secondary/60",
                  )}
                >
                  <span className="inline-flex min-w-0 items-center gap-1.5">
                    <input
                      type="checkbox"
                      className="size-3.5 accent-primary"
                      checked={selected.includes(info.name)}
                      disabled={saving}
                      onChange={() => toggle(info.name)}
                    />
                    <Wifi className="size-3.5 shrink-0 text-muted-foreground" />
                    <span className="truncate font-medium">{info.name}</span>
                    {INTERFACE_KIND_LABELS[info.kind] && (
                      <span className="text-2xs text-muted-foreground">
                        {INTERFACE_KIND_LABELS[info.kind]}
                      </span>
                    )}
                    {info.default_route && <Badge variant="secondary">default</Badge>}
                  </span>
                  <span className="shrink-0 text-2xs text-muted-foreground">
                    {interfaceState(info)}
                  </span>
                </label>
              ))}
            </div>
          ) : (
            <div className="flex flex-col gap-2 py-1">
              {Array.from({ length: 3 }, (_, index) => (
                <Skeleton key={index} className="h-7" />
              ))}
            </div>
          )
        }
      />
      {catalog?.warnings.length ? (
        <SettingRow
          column
          last
          title="Warnings"
          detail="These combinations can double-count or miss traffic."
          control={
            <ul className="grid gap-1.5">
              {catalog.warnings.map((warning) => (
                <li
                  key={`${warning.kind}:${warning.interfaces.join(",")}`}
                  className="flex items-start gap-2 text-2xs leading-relaxed text-warning"
                >
                  <TriangleAlert className="mt-px size-3.5 shrink-0" />
                  <span>{warning.message}</span>
                </li>
              ))}
            </ul>
          }
        />
      ) : null}
    </SettingsCard>
  );
}

function DomainCard({
  settings,
  saving,
  onDomainsEnabled,
  onDns,
  onSni,
  onHost,
}: {
  settings: SettingsData | undefined;
  saving: boolean;
  onDomainsEnabled: (checked: boolean) => void;
  onDns: (checked: boolean) => void;
  onSni: (checked: boolean) => void;
  onHost: (checked: boolean) => void;
}) {
  const domainsEnabled = settings?.domains.enabled ?? false;
  return (
    <SettingsCard title="Domain observation" description="Domain names are sensitive network metadata kept only on this device.">
      <SettingRow
        title="Observe domains"
        detail="Master switch for DNS answers, TLS SNI and HTTP Host."
        control={
          settings ? (
            <Switch checked={domainsEnabled} disabled={saving} onCheckedChange={onDomainsEnabled} />
          ) : (
            <Skeleton className="h-[26px] w-11 rounded-full" />
          )
        }
      />
      <SettingRow
        sub
        title="DNS answers"
        detail="Associates domains from local DNS responses within their TTL. Marked as inferred."
        disabled={!settings || !domainsEnabled}
        control={
          <Switch checked={settings?.domains.dns ?? false} disabled={saving || !domainsEnabled} onCheckedChange={onDns} />
        }
      />
      <SettingRow
        sub
        title="TLS SNI"
        detail="Reads the server name from the TLS ClientHello. ClientHello is not stored."
        disabled={!settings || !domainsEnabled}
        control={
          <Switch checked={settings?.domains.tls_sni ?? false} disabled={saving || !domainsEnabled} onCheckedChange={onSni} />
        }
      />
      <SettingRow
        sub
        last
        title="HTTP Host"
        detail="Reads the Host header from plaintext HTTP. URLs, headers and bodies are never stored."
        disabled={!settings || !domainsEnabled}
        control={
          <Switch checked={settings?.domains.http_host ?? false} disabled={saving || !domainsEnabled} onCheckedChange={onHost} />
        }
      />
      <p className="flex items-center gap-1.5 py-2.5 text-2xs text-muted-foreground">
        <Lock className="size-3.5" />
        Domain and IP metadata never leaves this device unless you export it yourself.
      </p>
    </SettingsCard>
  );
}

function HistoryCard({
  settings,
  saving,
  onHistoryEnabled,
  onRetention,
}: {
  settings: SettingsData | undefined;
  saving: boolean;
  onHistoryEnabled: (checked: boolean) => void;
  onRetention: (days: number) => void;
}) {
  const historyEnabled = settings?.history.enabled ?? false;
  return (
    <SettingsCard title="History" description="Retained flow records used by the Overview and lists.">
      <SettingRow
        title="Keep history"
        detail="When off, live views continue but nothing is retained."
        control={
          settings ? (
            <Switch checked={historyEnabled} disabled={saving} onCheckedChange={onHistoryEnabled} />
          ) : (
            <Skeleton className="h-[26px] w-11 rounded-full" />
          )
        }
      />
      <SettingRow
        last
        title="Retention"
        detail="Detailed records older than this are rolled up and dropped."
        disabled={!settings || !historyEnabled}
        control={
          <Segmented
            ariaLabel="Retention"
            disabled={!historyEnabled}
            value={settings ? String(settings.history.retention_days) : "7"}
            options={[
              { value: "1", label: "1 day" },
              { value: "7", label: "7 days" },
              { value: "30", label: "30 days" },
            ]}
            onChange={(value) => onRetention(Number(value))}
          />
        }
      />
    </SettingsCard>
  );
}

function ResourcesCard({
  settings,
  saving,
  onMaxFlowEntries,
  onDiskQuota,
}: {
  settings: SettingsData | undefined;
  saving: boolean;
  onMaxFlowEntries: (value: number) => void;
  onDiskQuota: (value: number) => void;
}) {
  return (
    <SettingsCard title="Resources" description="Upper bounds that keep the collector lightweight.">
      <SettingRow
        title="Max flow entries"
        detail="Kernel-side flow map capacity."
        control={
          <Select
            value={settings ? String(settings.resources.max_flow_entries) : undefined}
            onValueChange={(value) => onMaxFlowEntries(Number(value))}
            disabled={saving}
          >
            <SelectTrigger className="w-28 text-xs" size="sm" aria-label="Max flow entries">
              <SelectValue placeholder="—" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="16384">16,384</SelectItem>
              <SelectItem value="65536">65,536</SelectItem>
              <SelectItem value="262144">262,144</SelectItem>
            </SelectContent>
          </Select>
        }
      />
      <SettingRow
        last
        title="Disk quota"
        detail="Maximum storage for retained history."
        control={
          <Select
            value={settings ? String(settings.resources.disk_quota_mb) : undefined}
            onValueChange={(value) => onDiskQuota(Number(value))}
            disabled={saving}
          >
            <SelectTrigger className="w-28 text-xs" size="sm" aria-label="Disk quota">
              <SelectValue placeholder="—" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="128">128 MB</SelectItem>
              <SelectItem value="512">512 MB</SelectItem>
              <SelectItem value="2048">2 GB</SelectItem>
            </SelectContent>
          </Select>
        }
      />
    </SettingsCard>
  );
}

function ProxyCard({
  settings,
  status,
  saving,
  onPatch,
}: {
  settings: SettingsData | undefined;
  status: StatusData | undefined;
  saving: boolean;
  onPatch: (patch: Partial<ProxySettings>) => void;
}) {
  const proxy = settings?.proxy;
  const proxyStatus = status?.proxy;
  const [controllerUrl, setControllerUrl] = useState(proxy?.controller_url ?? "");
  const [secret, setSecret] = useState(proxy?.secret ?? "");

  useEffect(() => {
    setControllerUrl(proxy?.controller_url ?? "");
  }, [proxy?.controller_url]);
  useEffect(() => {
    setSecret(proxy?.secret ?? "");
  }, [proxy?.secret]);

  const commit = (field: keyof ProxySettings, value: string) => {
    if (settings && proxy && proxy[field] !== value) {
      onPatch({ [field]: value });
    }
  };

  const enabled = proxy?.enabled ?? false;
  return (
    <SettingsCard
      title="Proxy integration"
      description="Resolve fake-IP destinations through a local mihomo/Clash controller so countries and ASNs stay accurate."
    >
      <SettingRow
        title="Resolve via proxy API"
        detail="Polls the controller's /connections endpoint on this device only. Nothing leaves your network."
        control={
          settings ? (
            <Switch
              checked={enabled}
              disabled={saving}
              onCheckedChange={(checked) => onPatch({ enabled: checked })}
            />
          ) : (
            <Skeleton className="h-[26px] w-11 rounded-full" />
          )
        }
      />
      <SettingRow
        title="Controller URL"
        detail="http://host:port — mihomo's external-controller. http only for now."
        disabled={!settings || !enabled}
        control={
          <Input
            value={controllerUrl}
            placeholder="http://192.168.100.3:9090"
            spellCheck={false}
            autoComplete="off"
            disabled={saving || !enabled}
            onChange={(event) => setControllerUrl(event.target.value)}
            onBlur={() => commit("controller_url", controllerUrl.trim())}
            className="h-8 w-56 text-xs"
          />
        }
      />
      <SettingRow
        title="Secret"
        detail="mihomo external-controller secret. Stored locally in the agent database."
        disabled={!settings || !enabled}
        control={
          <Input
            type="password"
            value={secret}
            autoComplete="off"
            disabled={saving || !enabled}
            onChange={(event) => setSecret(event.target.value)}
            onBlur={() => commit("secret", secret.trim())}
            className="h-8 w-56 text-xs"
          />
        }
      />
      <SettingRow
        column
        last
        title="Status"
        detail="Controller reachability and resolved connections."
        control={
          <DefList
            compact
            rows={[
              { label: "Integration", value: enabled ? "Enabled" : "Disabled" },
              {
                label: "Controller",
                wrap: true,
                value: !enabled
                  ? "—"
                  : proxyStatus?.reachable
                    ? `Reachable · ${formatNumber(proxyStatus.mapped)} connections mapped`
                    : proxyStatus?.last_error ?? "Waiting for the first poll…",
              },
            ]}
          />
        }
      />
    </SettingsCard>
  );
}

function TrafficRulesCard({
  settings,
  status,
  saving,
  onMasterEnabled,
}: {
  settings: SettingsData | undefined;
  status: StatusData | undefined;
  saving: boolean;
  onMasterEnabled: (checked: boolean) => void;
}) {
  const rulesQuery = useTrafficRules();
  const updateRule = useUpdateTrafficRule();
  const deleteRule = useDeleteTrafficRule();
  const enforcement = status?.enforcement;
  const rules = rulesQuery.data ?? [];
  const notEnforced = enforcement?.available === false || settings?.traffic_rules.enabled === false;

  return (
    <SettingsCard
      title="Traffic rules"
      description="User-confirmed limits and blocks enforced at the device boundary."
      className="lg:col-span-2"
    >
      <div className="rounded-xl border bg-card/60 px-4">
        <SettingRow
          title="Enforcement"
          detail="One switch pauses every rule without deleting it."
          control={
            <Switch
              checked={settings?.traffic_rules.enabled ?? true}
              disabled={!settings || saving}
              onCheckedChange={onMasterEnabled}
            />
          }
          last
        />
      </div>

      {notEnforced && (
        <div className="mt-3 flex items-start gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/8 px-3.5 py-2.5">
          <TriangleAlert className="mt-px size-4 shrink-0 text-amber-500" />
          <div className="min-w-0">
            <strong className="block text-xs font-medium">Rules are not enforced</strong>
            <p className="mt-0.5 text-2xs leading-relaxed break-words text-muted-foreground">
              {enforcement?.available === false
                ? (enforcement.last_error ?? "The collector is not running.")
                : "The enforcement master switch is off."}
            </p>
          </div>
        </div>
      )}

      <div className="mt-3 rounded-xl border bg-card/60">
        {rulesQuery.isLoading ? (
          <div className="px-4 py-3">
            <Skeleton className="h-6 w-full" />
          </div>
        ) : rules.length === 0 ? (
          <p className="px-4 py-3 text-2xs text-muted-foreground">
            No rules yet. Right-click a connection, endpoint or application in the Explorer to add
            one.
          </p>
        ) : (
          <ul className="divide-y divide-border/60">
            {rules.map((rule) => (
              <li key={rule.id} className="flex items-center gap-3 px-4 py-2.5">
                <Badge variant={rule.action === "block" ? "destructive" : "secondary"}>
                  {rule.action === "block" ? "Block" : "Limit"}
                </Badge>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-mono text-xs">{ruleTarget(rule)}</span>
                    <span className="shrink-0 text-2xs text-muted-foreground">{directionLabel(rule.direction)}</span>
                  </div>
                  <p className="mt-0.5 text-2xs text-muted-foreground">
                    {rule.action === "limit"
                      ? formatRateText(rule.rate_bytes_per_s * 8)
                      : "all matching packets"}
                    {rule.counters && rule.counters.dropped_packets > 0
                      ? ` · ${formatNumber(rule.counters.dropped_packets)} dropped`
                      : ""}
                    {rule.state !== "active" ? ` · ${stateLabel(rule.state)}` : ""}
                  </p>
                </div>
                <Switch
                  checked={rule.enabled}
                  disabled={updateRule.isPending}
                  onCheckedChange={(checked) =>
                    updateRule.mutate({ id: rule.id, rule: { enabled: checked } })
                  }
                  aria-label="Rule enabled"
                />
                <Button
                  variant="ghost"
                  size="icon-sm"
                  disabled={deleteRule.isPending}
                  onClick={() =>
                    deleteRule.mutate(rule.id, {
                      onSuccess: () => toast.success("Rule deleted"),
                    })
                  }
                  aria-label="Delete rule"
                >
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </SettingsCard>
  );
}

function ruleTarget(rule: TrafficRule): string {
  const { selector } = rule;
  if (selector.kind === "application") return selector.id;
  if (selector.kind === "cidr") return `${selector.address}/${selector.prefix_len}`;
  return selector.port ? `${selector.address}:${selector.port}` : selector.address;
}

function stateLabel(state: TrafficRule["state"]): string {
  switch (state) {
    case "unresolved":
      return "unresolved";
    case "bypassed":
      return "not enforced";
    case "unavailable":
      return "agent unavailable";
    default:
      return "active";
  }
}

function DataCard({
  onExport,
  onClear,
  clearing,
}: {
  onExport: (format: "json" | "csv") => void;
  onClear: () => void;
  clearing: boolean;
}) {
  return (
    <SettingsCard title="Data" description="Take your diagnostics with you, or start clean.">
      <SettingRow
        title="Export diagnostics"
        detail="Flow metadata, evidence and IP profiles. Never payloads."
        control={
          <span className="flex shrink-0 gap-2">
            <Button variant="secondary" size="sm" onClick={() => onExport("json")}>
              <FileDown className="size-3.5" />
              JSON
            </Button>
            <Button variant="secondary" size="sm" onClick={() => onExport("csv")}>
              <FileText className="size-3.5" />
              CSV
            </Button>
          </span>
        }
      />
      <SettingRow
        column
        title="Recent exports"
        detail="JSON keeps evidence and IP profiles; CSV is Flow records only. Files expire automatically."
        control={<ExportTasks limit={4} className="w-full" />}
      />
      <SettingRow
        last
        title="Clear history"
        detail="Deletes retained flow records on this device. Cannot be undone."
        control={
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button variant="destructive" size="sm">
                <Trash2 className="size-3.5" />
                Clear…
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Clear retained history?</AlertDialogTitle>
                <AlertDialogDescription>
                  All stored flows, domain associations and rollups on this device will be deleted. Live collection
                  continues.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction
                  className="bg-destructive text-white hover:bg-destructive/90"
                  onClick={onClear}
                  disabled={clearing}
                >
                  {clearing ? <Loader2 className="size-4 animate-spin" /> : null}
                  Delete history
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        }
      />
    </SettingsCard>
  );
}

function AboutCard({ status }: { status: StatusData | undefined }) {
  return (
    <SettingsCard title="About" description="Service and database status.">
      {status ? (
        <div className="py-1">
          <DefList
            rows={[
              { label: "Version", value: `${status.version} · API ${status.api_version}` },
              { label: "Started", value: relativeTime(status.started_at) },
              { label: "Last batch", value: status.last_batch_at ? relativeTime(status.last_batch_at) : "—" },
              {
                label: "Fingerprints",
                value: `${formatNumber(status.fingerprints.rules)} rules${status.fingerprints.custom ? " · custom" : ""}`,
              },
              {
                label: "GeoIP database",
                wrap: true,
                value: status.enrichment.database_version
                  ? `${status.enrichment.database_version} · loaded ${
                      status.enrichment.loaded_at ? relativeTime(status.enrichment.loaded_at) : "unknown"
                    }`
                  : <span className="text-muted-foreground">Not available</span>,
              },
              {
                label: "Recent operations",
                wrap: true,
                value: status.recent_operations.length ? (
                  <span className="flex flex-col items-end">
                    {status.recent_operations.map((entry, index) => (
                      <span key={index}>
                        {entry.action} ({entry.outcome})
                      </span>
                    ))}
                  </span>
                ) : (
                  "—"
                ),
              },
            ]}
          />
        </div>
      ) : (
        <div className="flex flex-col gap-2 py-2.5">
          {Array.from({ length: 4 }, (_, index) => (
            <Skeleton key={index} className="h-6" />
          ))}
        </div>
      )}
    </SettingsCard>
  );
}
