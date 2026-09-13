/**
 * Shared filter controls: the network tri-state and the time filter with
 * relative presets plus an absolute window. Both are deliberately obvious
 * about what is applied so nobody has to guess what a control does.
 */

import { useState } from "react";
import { CalendarRange } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Segmented } from "@/components/segmented";
import { formatClock, formatDay } from "@/lib/format";
import type { NetworkFilter, TimeRange } from "@/types";

const NETWORK_OPTIONS = [
  { value: "all", label: "All" },
  { value: "internet", label: "Internet" },
  { value: "lan", label: "LAN" },
];

const RANGE_OPTIONS = [
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

/** Absolute window in Unix epoch milliseconds. */
export interface TimeWindow {
  start: number;
  end: number;
}

export function NetworkFilterControl({
  value,
  onChange,
}: {
  value: NetworkFilter;
  onChange: (value: NetworkFilter) => void;
}) {
  return (
    <Segmented
      ariaLabel="Network"
      options={NETWORK_OPTIONS}
      value={value}
      onChange={(next) => onChange(next as NetworkFilter)}
    />
  );
}

function toLocalInput(ms: number): string {
  const date = new Date(ms);
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function windowLabel(window: TimeWindow): string {
  const sameDay =
    new Date(window.start).toDateString() === new Date(window.end).toDateString();
  const from = sameDay
    ? formatClock(window.start)
    : `${formatDay(window.start)} ${formatClock(window.start)}`;
  return `${from} → ${formatClock(window.end)}`;
}

export function TimeFilter({
  range,
  custom,
  onRange,
  onCustom,
}: {
  range: TimeRange;
  custom: TimeWindow | null;
  onRange: (range: TimeRange) => void;
  onCustom: (window: TimeWindow | null) => void;
}) {
  const [open, setOpen] = useState(false);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");

  const openChange = (next: boolean) => {
    setOpen(next);
    if (next) {
      const now = Date.now();
      setStart(toLocalInput(custom?.start ?? now - 3_600_000));
      setEnd(toLocalInput(custom?.end ?? now));
    }
  };

  const apply = () => {
    const from = new Date(start).getTime();
    const to = new Date(end).getTime();
    if (!Number.isFinite(from) || !Number.isFinite(to)) {
      toast.error("Pick a start and end time");
      return;
    }
    if (from > to) {
      toast.error("Start must be before end");
      return;
    }
    onCustom({ start: from, end: to });
    setOpen(false);
  };

  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      <Segmented
        ariaLabel="Time range"
        options={RANGE_OPTIONS}
        value={custom ? "" : range}
        onChange={(value) => {
          onCustom(null);
          onRange(value as TimeRange);
        }}
      />
      <Popover open={open} onOpenChange={openChange}>
        <PopoverTrigger asChild>
          <Button
            variant={custom ? "secondary" : "outline"}
            size="sm"
            className={custom ? "tabular-nums" : undefined}
          >
            <CalendarRange className="size-3.5" />
            {custom ? windowLabel(custom) : "Custom"}
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-72">
          <div className="grid gap-3">
            <label className="grid gap-1">
              <span className="text-2xs font-medium text-muted-foreground">From</span>
              <Input
                type="datetime-local"
                value={start}
                onChange={(event) => setStart(event.target.value)}
                className="text-xs"
              />
            </label>
            <label className="grid gap-1">
              <span className="text-2xs font-medium text-muted-foreground">To</span>
              <Input
                type="datetime-local"
                value={end}
                onChange={(event) => setEnd(event.target.value)}
                className="text-xs"
              />
            </label>
            <div className="flex items-center justify-end gap-2">
              {custom && (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => {
                    onCustom(null);
                    setOpen(false);
                  }}
                >
                  Clear
                </Button>
              )}
              <Button size="sm" onClick={apply}>
                Apply
              </Button>
            </div>
          </div>
        </PopoverContent>
      </Popover>
    </span>
  );
}
