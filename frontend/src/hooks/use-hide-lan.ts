/**
 * "Internet only" preference: hides Flows whose remote peer is on the local
 * network. Persisted so Overview and Explorer agree; changes broadcast to any
 * mounted view.
 */

import { useCallback, useEffect, useState } from "react";
import { preferences } from "@/lib/preferences";

const CHANGE_EVENT = "zimascope:hide-lan";

export function useHideLan(): [boolean, (value: boolean) => void] {
  const [value, setValue] = useState(() => preferences.hideLan());

  useEffect(() => {
    const onChange = () => setValue(preferences.hideLan());
    window.addEventListener(CHANGE_EVENT, onChange);
    return () => window.removeEventListener(CHANGE_EVENT, onChange);
  }, []);

  const update = useCallback((next: boolean) => {
    preferences.setHideLan(next);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  }, []);

  return [value, update];
}
