/**
 * Appearance provider. The preference (system / light / dark) cycles like
 * macOS and persists in localStorage; the provider resolves "system" against
 * `prefers-color-scheme` and pins the resolved value on `<html data-theme>`,
 * which is what the CSS tokens and the Tailwind dark variant key off.
 */

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { preferences, type ThemePreference } from "@/lib/preferences";

interface ThemeContextValue {
  preference: ThemePreference;
  resolved: "light" | "dark";
  cycle: () => void;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

const ORDER: ThemePreference[] = ["system", "light", "dark"];

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [preference, setPreference] = useState<ThemePreference>(() => preferences.theme());
  const [resolved, setResolved] = useState<"light" | "dark">(() =>
    document.documentElement.dataset.theme === "dark" ? "dark" : "light",
  );

  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      const next = preference === "system" ? (media.matches ? "dark" : "light") : preference;
      document.documentElement.dataset.theme = next;
      setResolved(next);
    };
    apply();
    if (preference !== "system") return;
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [preference]);

  const cycle = useCallback(() => {
    setPreference((current) => {
      const next = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
      preferences.setTheme(next);
      return next;
    });
  }, []);

  const value = useMemo(() => ({ preference, resolved, cycle }), [preference, resolved, cycle]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const context = useContext(ThemeContext);
  if (!context) throw new Error("useTheme must be used inside ThemeProvider");
  return context;
}
