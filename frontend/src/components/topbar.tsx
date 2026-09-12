/**
 * Floating translucent topbar panel. Owns the route title (set by views),
 * optional view actions (e.g. the explore search field), the demo indicator
 * and the global refresh action. Floats clear of the icon rail: on lg the
 * panel starts right of the rail with a visible gutter instead of sliding
 * underneath it.
 */

import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { motion } from "motion/react";
import { PanelLeft, RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useTopbar } from "@/hooks/use-topbar";

export function Topbar({ onMenu }: { onMenu: () => void }) {
  const { info } = useTopbar();
  const queryClient = useQueryClient();
  const [spinning, setSpinning] = useState(false);

  const refresh = () => {
    setSpinning(true);
    void queryClient.invalidateQueries();
  };

  return (
    <header className="material-chrome floating-chrome sticky top-2 z-30 mx-3 mt-2 flex h-12 shrink-0 items-center gap-3 rounded-xl px-4 sm:px-6 lg:mr-3 lg:ml-2 lg:pl-7">
      <Button
        variant="ghost"
        size="icon-sm"
        className="-ml-1.5 lg:hidden"
        onClick={onMenu}
        aria-label="Open navigation"
      >
        <PanelLeft className="size-[18px]" strokeWidth={1.7} />
      </Button>

      <div className="min-w-0">
        <h1 className="truncate text-base leading-tight font-semibold tracking-[0.01em]">{info.title}</h1>
        {info.meta && <p className="truncate text-2xs text-muted-foreground">{info.meta}</p>}
      </div>

      <div className="ml-auto flex items-center gap-2">
        {info.trailing}
        <Button variant="secondary" size="sm" onClick={refresh} title="Refresh">
          <motion.span
            className="grid"
            animate={spinning ? { rotate: 360 } : { rotate: 0 }}
            transition={{ duration: 0.52, ease: [0.32, 0.72, 0, 1] }}
            onAnimationComplete={() => setSpinning(false)}
          >
            <RotateCw className="size-3.5" />
          </motion.span>
          Refresh
        </Button>
      </div>
    </header>
  );
}
