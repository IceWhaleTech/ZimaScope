/**
 * Network filter shared by Overview and Explorer: everything, internet only
 * (LAN hidden), or LAN only. Persisted so both views agree; the legacy
 * boolean `hide-lan` preference maps to `internet`.
 */

import { useCallback, useEffect, useState } from "react";
import { preferences } from "@/lib/preferences";
import type { NetworkFilter } from "@/types";

const CHANGE_EVENT = "zimascope:network-filter";

export function useNetworkFilter(): [NetworkFilter, (value: NetworkFilter) => void] {
  const [value, setValue] = useState<NetworkFilter>(() => preferences.networkFilter());

  useEffect(() => {
    const onChange = () => setValue(preferences.networkFilter());
    window.addEventListener(CHANGE_EVENT, onChange);
    return () => window.removeEventListener(CHANGE_EVENT, onChange);
  }, []);

  const update = useCallback((next: NetworkFilter) => {
    preferences.setNetworkFilter(next);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  }, []);

  return [value, update];
}
