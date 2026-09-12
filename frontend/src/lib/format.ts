/** Human-readable formatting for network telemetry. */

import type { Confidence, Evidence, Scope, TimeRange } from "../types";

export function formatBytes(value: number, digits = 1): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Math.max(0, value);
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit += 1;
  }
  return `${size.toFixed(unit > 1 ? digits : 0)} ${units[unit]}`;
}

export function formatRate(bps: number): { value: string; unit: string } {
  if (bps >= 1_000_000_000) return { value: (bps / 1_000_000_000).toFixed(2), unit: "Gbps" };
  if (bps >= 1_000_000) return { value: (bps / 1_000_000).toFixed(bps >= 10_000_000 ? 1 : 2), unit: "Mbps" };
  if (bps >= 1_000) return { value: (bps / 1_000).toFixed(0), unit: "Kbps" };
  return { value: bps.toFixed(0), unit: "bps" };
}

export function formatRateText(bps: number): string {
  const rate = formatRate(bps);
  return `${rate.value} ${rate.unit}`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

export function formatPercent(ratio: number, digits = 0): string {
  return `${(ratio * 100).toFixed(digits)}%`;
}

export function relativeTime(timestamp: number): string {
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 2) return "now";
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function formatDuration(ms: number): string {
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

export function formatClock(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function formatDay(timestamp: number): string {
  return new Date(timestamp).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export function flagEmoji(country: string | null | undefined): string {
  if (!country || country.length !== 2) return "";
  return String.fromCodePoint(...[...country.toUpperCase()].map((char) => 127397 + char.charCodeAt(0)));
}

export function evidenceLabel(evidence: Evidence): string {
  switch (evidence) {
    case "dns":
      return "DNS";
    case "tls_sni":
      return "TLS SNI";
    case "http_host":
      return "HTTP Host";
  }
}

export function evidenceTitle(evidence: Evidence): string {
  switch (evidence) {
    case "dns":
      return "Inferred from a DNS answer inside its TTL";
    case "tls_sni":
      return "Direct from the TLS ClientHello SNI";
    case "http_host":
      return "Direct from a plaintext HTTP Host header";
  }
}

export function confidenceLabel(confidence: Confidence): string {
  return confidence === "direct" ? "Direct" : "Inferred";
}

export function scopeLabel(scope: Scope): string {
  switch (scope) {
    case "public":
      return "Public";
    case "private":
      return "Private";
    case "shared":
      return "Carrier NAT";
    case "fake_ip":
      return "Fake IP";
    case "loopback":
      return "Loopback";
    case "link_local":
      return "Link-local";
    case "unique_local":
      return "Unique local";
    case "multicast":
      return "Multicast";
    case "broadcast":
      return "Broadcast";
    case "documentation":
      return "Documentation";
    case "reserved":
      return "Reserved";
    case "unspecified":
      return "Unspecified";
  }
}

/** Network column: the LAN has no ASN organization, so say LAN; unknown is "—". */
export function networkLabel(scope: Scope, organization?: string | null): string {
  if (organization) return organization;
  if (scope === "private" || scope === "link_local" || scope === "unique_local") {
    return "LAN";
  }
  return "—";
}

export function rangeLabel(range: TimeRange): string {
  switch (range) {
    case "15m":
      return "15 minutes";
    case "1h":
      return "1 hour";
    case "24h":
      return "24 hours";
    case "7d":
      return "7 days";
  }
}
