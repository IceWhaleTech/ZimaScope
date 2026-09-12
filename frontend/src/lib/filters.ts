import type { Scope } from "@/types";

/** Scopes treated as local network by the "Internet only" filter. */
export const LAN_SCOPES: Scope[] = ["private", "link_local", "unique_local", "loopback"];

/** `exclude_scope` query value for the current filter state. */
export function excludeScopeParam(hideLan: boolean): string | undefined {
  return hideLan ? LAN_SCOPES.join(",") : undefined;
}

/** Parses an `exclude_scope` value back into a scope set. */
export function parseExcludeScope(value: string | undefined): Set<Scope> {
  const scopes = (value ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean) as Scope[];
  return new Set(scopes);
}
