import type { NetworkFilter, Scope } from "@/types";

/** Scopes treated as the local network by the shared network filter. */
export const LAN_SCOPES: Scope[] = ["private", "link_local", "unique_local", "loopback"];

/** `scope` query value for the current network filter (LAN only). */
export function scopeParam(filter: NetworkFilter): string | undefined {
  return filter === "lan" ? LAN_SCOPES.join(",") : undefined;
}

/** `exclude_scope` query value for the current network filter (internet only). */
export function excludeScopeParam(filter: NetworkFilter): string | undefined {
  return filter === "internet" ? LAN_SCOPES.join(",") : undefined;
}

/** Parses an `exclude_scope` value back into a scope set. */
export function parseExcludeScope(value: string | undefined): Set<Scope> {
  const scopes = (value ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean) as Scope[];
  return new Set(scopes);
}
