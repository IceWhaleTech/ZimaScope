/** Small persisted UI preferences. */

const THEME_KEY = "zimascope.theme";
const HIDE_LAN_KEY = "zimascope.hide-lan";

export type ThemePreference = "system" | "light" | "dark";

export const preferences = {
  theme(): ThemePreference {
    const value = localStorage.getItem(THEME_KEY);
    return value === "light" || value === "dark" ? value : "system";
  },
  setTheme(theme: ThemePreference): void {
    if (theme === "system") localStorage.removeItem(THEME_KEY);
    else localStorage.setItem(THEME_KEY, theme);
  },
  hideLan(): boolean {
    return localStorage.getItem(HIDE_LAN_KEY) === "true";
  },
  setHideLan(value: boolean): void {
    if (value) localStorage.setItem(HIDE_LAN_KEY, "true");
    else localStorage.removeItem(HIDE_LAN_KEY);
  },
};
