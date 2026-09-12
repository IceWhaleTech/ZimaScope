/**
 * Viewport windowing for the Explore table.
 *
 * The table keeps its full height with leading/trailing spacer rows and only
 * mounts the rows near the viewport, so a list that grows to thousands of
 * rows stays cheap to reconcile and paint while scrolling.
 */

import { useCallback, useEffect, useRef, useState, type RefObject } from "react";

/** Measured height of an Explore table row; the window math assumes it. */
export const TABLE_ROW_HEIGHT = 50;

export type RowWindow = { start: number; end: number };

export function useWindowedRows(
  containerRef: RefObject<HTMLElement | null>,
  count: number,
  rowHeight: number = TABLE_ROW_HEIGHT,
  overscan = 10,
): RowWindow {
  const [rowWindow, setRowWindow] = useState<RowWindow>({ start: 0, end: count });
  const frameRef = useRef(0);
  const countRef = useRef(count);
  countRef.current = count;

  const measure = useCallback(() => {
    frameRef.current = 0;
    const node = containerRef.current;
    if (!node) return;
    const total = countRef.current;
    if (total === 0) {
      setRowWindow((previous) =>
        previous.start === 0 && previous.end === 0 ? previous : { start: 0, end: 0 },
      );
      return;
    }
    const rect = node.getBoundingClientRect();
    const viewportHeight = window.innerHeight;
    const first = Math.floor((0 - rect.top) / rowHeight) - overscan;
    const last = Math.ceil((viewportHeight - rect.top) / rowHeight) + overscan;
    const start = Math.max(0, Math.min(first, total - 1));
    const end = Math.max(start, Math.min(last, total));
    setRowWindow((previous) =>
      previous.start === start && previous.end === end ? previous : { start, end },
    );
  }, [containerRef, rowHeight, overscan]);

  const schedule = useCallback(() => {
    if (frameRef.current === 0) frameRef.current = requestAnimationFrame(measure);
  }, [measure]);

  // Re-measure after every render: layout above the table (filters, morph
  // animation) can move it without a scroll event.
  useEffect(() => {
    schedule();
  });

  useEffect(() => {
    window.addEventListener("scroll", schedule, { passive: true });
    window.addEventListener("resize", schedule);
    return () => {
      window.removeEventListener("scroll", schedule);
      window.removeEventListener("resize", schedule);
    };
  }, [schedule]);

  useEffect(
    () => () => {
      if (frameRef.current) {
        cancelAnimationFrame(frameRef.current);
        frameRef.current = 0;
      }
    },
    [],
  );

  return rowWindow;
}
