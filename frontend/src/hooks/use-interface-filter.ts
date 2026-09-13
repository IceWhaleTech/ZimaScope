/**
 * Interface selector shared by Overview, Explorer and the detail timelines:
 * one Device Boundary interface, or every interface. Persisted so the views
 * agree on which boundary slice is on screen.
 */

import { useCallback, useEffect, useState } from "react";
import { preferences } from "@/lib/preferences";

const CHANGE_EVENT = "zimascope:interface-filter";

export function useInterfaceFilter(): [string, (value: string) => void] {
  const [value, setValue] = useState<string>(() => preferences.interfaceFilter());

  useEffect(() => {
    const onChange = () => setValue(preferences.interfaceFilter());
    window.addEventListener(CHANGE_EVENT, onChange);
    return () => window.removeEventListener(CHANGE_EVENT, onChange);
  }, []);

  const update = useCallback((next: string) => {
    preferences.setInterfaceFilter(next);
    window.dispatchEvent(new Event(CHANGE_EVENT));
  }, []);

  return [value, update];
}
