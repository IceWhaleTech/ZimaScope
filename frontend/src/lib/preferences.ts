/** Small persisted UI preferences. */

import type { NetworkFilter } from "../types";

const THEME_KEY = "zimascope.theme";
const NETWORK_KEY = "zimascope.network-filter";
const LEGACY_HIDE_LAN_KEY = "zimascope.hide-lan";

export type ThemePreference = "system" | "light" | "dark";

function isNetworkFilter(value: string | null): value is NetworkFilter {
  return value === "all" || value === "internet" || value === "lan";
}

export const preferences = {
  theme(): ThemePreference {
    const value = localStorage.getItem(THEME_KEY);
    return value === "light" || value === "dark" ? value : "system";
  },
  setTheme(theme: ThemePreference): void {
    if (theme === "system") localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, theme);
  },
  networkFilter(): NetworkFilter {
    const value = localStorage.getItem(NETWORK_KEY);
    if (isNetworkFilter(value)) return value;
    // Legacy `hide-lan=true` meant "internet only".
    return localStorage.getItem(LEGACY_HIDE_LAN_KEY) === "true" ? "internet" : "all";
  },
  setNetworkFilter(value: NetworkFilter): void {
    if (value === "all") localStorage.removeItem(NETWORK_KEY);
    else localStorage.setItem(NETWORK_KEY, value);
  },
};
