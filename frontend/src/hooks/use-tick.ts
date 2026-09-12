/**
 * Live tick access. The store owns the SSE connection; this hook bridges it
 * into React via `useSyncExternalStore` so every consumer re-renders on the
 * same tick without prop drilling.
 *
 * `subscribe` must keep a stable identity: React re-subscribes whenever it
 * changes, and re-subscribing here would close and reopen the SSE stream on
 * every render.
 */

import { useSyncExternalStore } from "react";
import { subscribeTicks } from "@/store";
import type { Tick } from "@/types";

let latest: Tick | null = null;

function subscribe(onChange: () => void): () => void {
  return subscribeTicks((tick) => {
    latest = tick;
    onChange();
  });
}

function snapshot(): Tick | null {
  return latest;
}

function serverSnapshot(): Tick | null {
  return null;
}

export function useTick(): Tick | null {
  return useSyncExternalStore(subscribe, snapshot, serverSnapshot);
}
