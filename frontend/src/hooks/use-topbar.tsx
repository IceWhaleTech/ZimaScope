/**
 * Topbar state. Views own their title and meta line; the shell renders it.
 * Kept as a tiny context instead of per-view portals so the topbar never
 * flickers between route transitions.
 */

import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

interface TopbarInfo {
  title: string;
  meta: string;
  /** View-owned actions rendered at the bar's trailing edge (e.g. search). */
  trailing?: ReactNode;
}

interface TopbarContextValue {
  info: TopbarInfo;
  setInfo: (info: TopbarInfo) => void;
}

const TopbarContext = createContext<TopbarContextValue | null>(null);

export function TopbarProvider({ children }: { children: ReactNode }) {
  const [info, setInfo] = useState<TopbarInfo>({ title: "Overview", meta: "" });
  const value = useMemo(() => ({ info, setInfo }), [info]);
  useEffect(() => {
    document.title = `${info.title} · ZimaScope`;
  }, [info.title]);
  return <TopbarContext.Provider value={value}>{children}</TopbarContext.Provider>;
}

export function useTopbar(): TopbarContextValue {
  const context = useContext(TopbarContext);
  if (!context) throw new Error("useTopbar must be used inside TopbarProvider");
  return context;
}

/** Declare the topbar heading for the mounted view. `trailing` optionally
    renders view-owned actions (like the explore search field) at the bar's
    right edge; pass a memoized node so the bar doesn't churn every render. */
export function useSetTopbar(title: string, meta = "", trailing?: ReactNode): void {
  const { setInfo } = useTopbar();
  useEffect(() => {
    setInfo({ title, meta, trailing });
  }, [title, meta, trailing, setInfo]);
}
