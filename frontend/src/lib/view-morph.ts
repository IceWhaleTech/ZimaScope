/**
 * Shared-element support for the Overview → Explorer handoff.
 *
 * The Recent flows table and the Explorer table carry the same
 * `view-transition-name`, so browsers with the View Transitions API morph one
 * surface into the other. The pending flag tells the layout to skip its route
 * enter animation for exactly that navigation: otherwise the new snapshot
 * would be captured mid fade and the morph would look broken.
 */

import { flushSync } from "react-dom";

let surfaceMorphPending = false;

/** Marks the next route change as a surface morph. */
export function markSurfaceMorph(): void {
  surfaceMorphPending = true;
}

/** Consumes the mark; the layout asks once per route change. */
export function consumeSurfaceMorph(): boolean {
  const pending = surfaceMorphPending;
  surfaceMorphPending = false;
  return pending;
}

type ViewTransitionDocument = Document & {
  startViewTransition?: (update: () => void) => { finished: Promise<void> };
};

/** Runs `update` inside a view transition when the browser supports one. */
export function runViewTransition(update: () => void): void {
  const doc = document as ViewTransitionDocument;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!doc.startViewTransition || reduced) {
    update();
    return;
  }
  doc.startViewTransition(() => {
    flushSync(update);
  });
}
