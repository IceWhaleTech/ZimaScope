/**
 * Dependency-light Recharts views: the boundary traffic timeline (dual series
 * area chart with a material tooltip) and the hero sparkline. Series colors
 * come from the theme tokens so charts follow light/dark automatically.
 */

import { useMemo } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { formatBytes, formatClock, formatDay, formatRateText } from "@/lib/format";
import type { TimelinePoint } from "@/types";

const inboundColor = "var(--series-inbound)";
const outboundColor = "var(--series-outbound)";

/** Per-interval bits-per-second series for the hero sparklines. */
export function rateSeries(points: TimelinePoint[]): { inbound: number[]; outbound: number[] } {
  const seconds = points.length > 1 ? (points[1].start - points[0].start) / 1000 : 60;
  const toBps = (bytes: number) => (seconds > 0 ? (bytes * 8) / seconds : 0);
  return {
    inbound: points.map((point) => toBps(point.inbound.bytes)),
    outbound: points.map((point) => toBps(point.outbound.bytes)),
  };
}

interface TimelineDatum {
  start: number;
  inbound: number;
  outbound: number;
}

export function TimelineChart({ points, heightClass = "h-56" }: { points: TimelinePoint[]; heightClass?: string }) {
  const data = useMemo<TimelineDatum[]>(
    () =>
      points.map((point) => ({
        start: point.start,
        inbound: point.inbound.bytes,
        outbound: point.outbound.bytes,
      })),
    [points],
  );
  const hourly = points.length > 0 && points[1] ? points[1].start - points[0].start >= 3_600_000 : false;

  return (
    <div className={`${heightClass} w-full`}>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 8, right: 4, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id="timeline-inbound" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={inboundColor} stopOpacity={0.22} />
              <stop offset="100%" stopColor={inboundColor} stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="timeline-outbound" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={outboundColor} stopOpacity={0.22} />
              <stop offset="100%" stopColor={outboundColor} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeWidth={1} />
          <XAxis
            dataKey="start"
            scale="time"
            type="number"
            domain={["dataMin", "dataMax"]}
            tickFormatter={(value: number) => (hourly ? formatDay(value) : formatClock(value))}
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
            minTickGap={56}
            tickMargin={8}
          />
          <YAxis
            tickFormatter={(value: number) => formatBytes(value, 0)}
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 11, fill: "var(--muted-foreground)" }}
            width={44}
          />
          <Tooltip
            cursor={{ stroke: "var(--muted-foreground)", strokeWidth: 1, strokeDasharray: "3 3" }}
            content={<TimelineTooltip />}
            isAnimationActive={false}
          />
          <Area
            dataKey="inbound"
            name="Inbound"
            stroke={inboundColor}
            strokeWidth={1.8}
            fill="url(#timeline-inbound)"
            isAnimationActive={false}
          />
          <Area
            dataKey="outbound"
            name="Outbound"
            stroke={outboundColor}
            strokeWidth={1.8}
            fill="url(#timeline-outbound)"
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

function TimelineTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: Array<{ name?: string; dataKey?: string; value?: number }>;
  label?: number | string;
}) {
  if (!active || !payload?.length) return null;
  const start = typeof label === "number" ? label : Number(label);
  return (
    <div className="material-overlay w-40 rounded-lg border border-border/70 p-2.5 shadow-pop">
      <p className="mb-1.5 text-2xs text-muted-foreground">
        {formatClock(start)}
        {Number.isFinite(start) && new Date(start).getHours() === 0 ? ` · ${formatDay(start)}` : ""}
      </p>
      {payload.map((entry) => (
        <p key={entry.dataKey} className="flex items-center justify-between gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5">
            <i
              className="size-1.5 rounded-full"
              style={{
                background: entry.dataKey === "inbound" ? inboundColor : outboundColor,
              }}
            />
            {entry.name}
          </span>
          <span className="font-medium tabular-nums">{formatBytes(entry.value ?? 0)}</span>
        </p>
      ))}
    </div>
  );
}

/** Tiny live-rate sparkline for the hero cards. */
export function Sparkline({ values, series }: { values: number[]; series: "inbound" | "outbound" }) {
  const data = useMemo(
    () => (values.length > 1 ? values.map((value, index) => ({ index, value })) : []),
    [values],
  );
  const color = series === "inbound" ? inboundColor : outboundColor;
  const id = `spark-${series}`;
  if (data.length < 2) return <div className="h-10" />;
  return (
    <div className="h-10 w-full" aria-hidden>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.25} />
              <stop offset="100%" stopColor={color} stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <YAxis hide domain={[0, "dataMax"]} />
          <Area
            dataKey="value"
            stroke={color}
            strokeWidth={1.5}
            fill={`url(#${id})`}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

export function formatSeriesRate(bps: number): string {
  return formatRateText(bps);
}
