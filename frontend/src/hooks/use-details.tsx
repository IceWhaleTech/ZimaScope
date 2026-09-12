/**
 * Detail panel controller. Any view can ask to inspect a flow, endpoint,
 * domain or application; the shell renders the right builder inside the side
 * Sheet. Deep links (`?flow=`, `?address=`, `?domain=`) open it on mount the
 * same way.
 */

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

export type DetailTarget =
  | { kind: "flow"; id: string }
  | { kind: "endpoint"; address: string }
  | { kind: "domain"; name: string }
  | { kind: "application"; id: string };

interface DetailsContextValue {
  target: DetailTarget | null;
  open: (target: DetailTarget) => void;
  close: () => void;
}

const DetailsContext = createContext<DetailsContextValue | null>(null);

export function DetailsProvider({ children }: { children: ReactNode }) {
  const [target, setTarget] = useState<DetailTarget | null>(null);
  const open = useCallback((next: DetailTarget) => setTarget(next), []);
  const close = useCallback(() => setTarget(null), []);
  const value = useMemo(() => ({ target, open, close }), [target, open, close]);
  return <DetailsContext.Provider value={value}>{children}</DetailsContext.Provider>;
}

export function useDetails(): DetailsContextValue {
  const context = useContext(DetailsContext);
  if (!context) throw new Error("useDetails must be used inside DetailsProvider");
  return context;
}
