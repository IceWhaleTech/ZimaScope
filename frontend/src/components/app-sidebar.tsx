/** Compact icon rail for primary navigation and global controls. */

import type { ReactNode } from "react";
import { Link, useLocation } from "react-router";
import {
  ArrowLeftRight,
  FileChartColumn,
  Globe2,
  Moon,
  Palette,
  Settings,
  Sun,
} from "lucide-react";
import { StatusDot } from "@/components/flow-bits";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { useTick } from "@/hooks/use-tick";
import { useStatus } from "@/hooks/use-data";
import { useTheme } from "@/hooks/use-theme";
import { cn } from "@/lib/utils";
import type { CollectorHealth } from "@/types";

const NAV = [
  { to: "/overview", label: "Overview", icon: Globe2, match: ["/overview"] },
  { to: "/explore", label: "Explore", icon: ArrowLeftRight, match: ["/explore", "/flows", "/endpoints", "/domains"] },
] as const;

const railItem =
  "relative grid h-9 w-10 shrink-0 place-items-center rounded-md text-muted-foreground transition-colors hover:bg-accent/70 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/40";

export function AppSidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { pathname } = useLocation();

  return (
    <TooltipProvider delayDuration={250}>
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/25 lg:hidden"
          onClick={onClose}
          aria-hidden
        />
      )}
      <aside
        aria-label="Primary"
        className={cn(
          "material-chrome floating-chrome fixed inset-y-2 left-2 z-50 flex w-14 flex-col items-center rounded-xl px-2 py-2.5 transition-transform duration-300 ease-[cubic-bezier(0.32,0.72,0,1)]",
          open ? "translate-x-0" : "-translate-x-full lg:translate-x-0",
        )}
      >
        <nav className="flex flex-col gap-0.5" aria-label="Main navigation">
          {NAV.map(({ to, label, icon: Icon, match }) => {
            const active = match.some((path) => pathname.startsWith(path));
            return (
              <RailTooltip key={to} label={label}>
                <Link
                  to={to}
                  onClick={onClose}
                  aria-label={label}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    railItem,
                    active && "bg-card/80 text-foreground shadow-sm dark:bg-black/55",
                  )}
                >
                  <Icon className="size-[18px]" strokeWidth={1.7} />
                </Link>
              </RailTooltip>
            );
          })}
        </nav>

        <div className="mt-auto flex flex-col gap-0.5">
          <BoundaryStatus />
          <ThemeToggle />
          <SettingsLink active={pathname.startsWith("/settings")} onClose={onClose} />
        </div>
      </aside>
    </TooltipProvider>
  );
}

function RailTooltip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>{children}</TooltipTrigger>
      <TooltipContent side="right" sideOffset={10}>
        {label}
      </TooltipContent>
    </Tooltip>
  );
}

function SettingsLink({ active, onClose }: { active: boolean; onClose: () => void }) {
  return (
    <RailTooltip label="Settings">
      <Link
        to="/settings"
        onClick={onClose}
        aria-label="Settings"
        aria-current={active ? "page" : undefined}
        className={cn(
          railItem,
          active && "bg-card/80 text-foreground shadow-sm dark:bg-black/55",
        )}
      >
        <Settings className="size-[18px]" strokeWidth={1.7} />
      </Link>
    </RailTooltip>
  );
}

function boundaryOf(health: CollectorHealth | null | undefined): {
  state: "running" | "degraded" | "stopped";
  label: string;
  detail: string;
} {
  if (!health) {
    return { state: "stopped", label: "Collector offline", detail: "No interface attached" };
  }
  const attached = health.interfaces.every((entry) => entry.ingress_attached && entry.egress_attached);
  const names = health.interfaces.map((entry) => entry.name).join(", ") || "no interface";
  return {
    state: health.state === "running" && attached ? "running" : "degraded",
    label: health.state === "running" ? "Observing" : `Collector ${health.state}`,
    detail: `Boundary ${names}`,
  };
}

function BoundaryStatus() {
  const tick = useTick();
  const statusQuery = useStatus();
  const health = tick?.health ?? statusQuery.data?.collector ?? null;
  const resolved = health
    ? boundaryOf(health)
    : statusQuery.isSuccess
      ? boundaryOf(null)
      : { state: "stopped" as const, label: "Connecting...", detail: "Waiting for collector" };

  return (
    <RailTooltip label={`${resolved.label} - ${resolved.detail}`}>
      <div className={railItem} role="status" aria-label={`${resolved.label}. ${resolved.detail}`}>
        <FileChartColumn className="size-[18px]" strokeWidth={1.7} />
        <span className="absolute right-2.5 top-2 grid size-2.5 place-items-center rounded-full bg-card">
          <StatusDot state={resolved.state} />
        </span>
      </div>
    </RailTooltip>
  );
}

function ThemeToggle() {
  const { preference, cycle } = useTheme();
  const label = preference === "system" ? "Auto appearance" : preference === "light" ? "Light appearance" : "Dark appearance";

  return (
    <RailTooltip label={label}>
      <button type="button" onClick={cycle} aria-label={`${label}. Change appearance`} className={railItem}>
        <Palette className="size-[18px]" strokeWidth={1.7} />
        <span className="absolute bottom-1.5 right-2 grid size-3 place-items-center rounded-full bg-card shadow-sm">
          {preference === "dark" ? (
            <Moon className="size-2 text-foreground" strokeWidth={2} />
          ) : (
            <Sun className="size-2 text-warning" strokeWidth={2} />
          )}
        </span>
      </button>
    </RailTooltip>
  );
}
