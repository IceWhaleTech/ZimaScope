/**
 * Hand-rolled SVG charts: the boundary traffic timeline (dual-series area
 * chart with a material tooltip) and the hero sparkline.
 *
 * These are drawn directly instead of pulling in a charting library, because
 * the whole bundle ships embedded inside the agent binary. Series colors come
 * from the theme tokens so charts follow light/dark automatically.
 */

import { useEffect, useMemo, useRef, useState } from "react";
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

/** Rounds a value up to a 1/2/5 x 10^n grid so axis labels stay stable. */
function niceCeil(value: number): number {
  if (value <= 0) return 1;
  const exponent = Math.floor(Math.log10(value));
  const base = 10 ** exponent;
  const scaled = value / base;
  const nice = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
  return nice * base;
}

function linePath(points: Array<[number, number]>): string {
  return points.map(([x, y], index) => `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
}

interface TimelineDatum {
  start: number;
  inbound: number;
  outbound: number;
}

const PADDING = { top: 8, right: 4, bottom: 20, left: 44 };

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
  const hourly = points.length > 1 && points[1].start - points[0].start >= 3_600_000;
  const containerRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ width: 0, height: 0 });
  const [hover, setHover] = useState<number | null>(null);

  useEffect(() => {
    const node = containerRef.current;
    if (!node) return;
    const update = () => setSize({ width: node.clientWidth, height: node.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const geometry = useMemo(() => {
    if (data.length < 2 || size.width <= 0 || size.height <= 0) return null;
    const plotWidth = size.width - PADDING.left - PADDING.right;
    const plotHeight = size.height - PADDING.top - PADDING.bottom;
    if (plotWidth <= 0 || plotHeight <= 0) return null;
    const max = niceCeil(
      Math.max(...data.flatMap((point) => [point.inbound, point.outbound]), 1),
    );
    const xFor = (index: number) =>
      PADDING.left + (index / (data.length - 1)) * plotWidth;
    const yFor = (value: number) =>
      PADDING.top + plotHeight - (value / max) * plotHeight;
    const inbound = data.map((point, index): [number, number] => [xFor(index), yFor(point.inbound)]);
    const outbound = data.map((point, index): [number, number] => [xFor(index), yFor(point.outbound)]);
    const baseline = PADDING.top + plotHeight;
    const ticks = Math.min(4, Math.max(2, Math.round(plotWidth / 90)));
    const xTicks = Array.from({ length: ticks + 1 }, (_, step) =>
      Math.round((step / ticks) * (data.length - 1)),
    ).filter((index, position, all) => all.indexOf(index) === position);
    return {
      plotWidth,
      plotHeight,
      max,
      xFor,
      yFor,
      baseline,
      inbound,
      outbound,
      xTicks,
      yTicks: [0, 1, 2, 3].map((step) => (step / 3) * max),
    };
  }, [data, size]);

  const hoverDatum = geometry && hover !== null ? data[hover] : null;

  return (
    <div
      ref={containerRef}
      className={`relative ${heightClass} w-full`}
      onMouseLeave={() => setHover(null)}
      onMouseMove={
        geometry
          ? (event) => {
              const rect = event.currentTarget.getBoundingClientRect();
              const ratio = (event.clientX - rect.left - PADDING.left) / geometry.plotWidth;
              const index = Math.round(ratio * (data.length - 1));
              setHover(Math.min(data.length - 1, Math.max(0, index)));
            }
          : undefined
      }
    >
      {geometry && (
        <svg width={size.width} height={size.height} className="block" aria-hidden>
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

          {geometry.yTicks.map((value) => (
            <g key={value}>
              <line
                x1={PADDING.left}
                x2={size.width - PADDING.right}
                y1={geometry.yFor(value)}
                y2={geometry.yFor(value)}
                stroke="var(--border)"
                strokeWidth={1}
              />
              <text
                x={PADDING.left - 6}
                y={geometry.yFor(value) + 3}
                textAnchor="end"
                fontSize={11}
                fill="var(--muted-foreground)"
              >
                {formatBytes(value, 0)}
              </text>
            </g>
          ))}

          {geometry.xTicks.map((index) => (
            <text
              key={index}
              x={geometry.xFor(index)}
              y={size.height - 6}
              textAnchor={
                index === 0 ? "start" : index === data.length - 1 ? "end" : "middle"
              }
              fontSize={11}
              fill="var(--muted-foreground)"
            >
              {hourly ? formatDay(data[index].start) : formatClock(data[index].start)}
            </text>
          ))}

          <path
            d={`${linePath(geometry.inbound)} L${geometry.xFor(data.length - 1)},${geometry.baseline} L${PADDING.left},${geometry.baseline} Z`}
            fill="url(#timeline-inbound)"
          />
          <path
            d={`${linePath(geometry.outbound)} L${geometry.xFor(data.length - 1)},${geometry.baseline} L${PADDING.left},${geometry.baseline} Z`}
            fill="url(#timeline-outbound)"
          />
          <path d={linePath(geometry.inbound)} fill="none" stroke={inboundColor} strokeWidth={1.8} />
          <path d={linePath(geometry.outbound)} fill="none" stroke={outboundColor} strokeWidth={1.8} />

          {hover !== null && (
            <g>
              <line
                x1={geometry.xFor(hover)}
                x2={geometry.xFor(hover)}
                y1={PADDING.top}
                y2={geometry.baseline}
                stroke="var(--muted-foreground)"
                strokeWidth={1}
                strokeDasharray="3 3"
              />
              <circle
                cx={geometry.xFor(hover)}
                cy={geometry.yFor(data[hover].inbound)}
                r={3}
                fill={inboundColor}
              />
              <circle
                cx={geometry.xFor(hover)}
                cy={geometry.yFor(data[hover].outbound)}
                r={3}
                fill={outboundColor}
              />
            </g>
          )}
        </svg>
      )}

      {hoverDatum && geometry && (
        <TimelineTooltip
          datum={hoverDatum}
          style={{
            left: Math.min(
              Math.max(geometry.xFor(hover ?? 0), 88),
              Math.max(88, size.width - 88),
            ),
          }}
        />
      )}
    </div>
  );
}

function TimelineTooltip({
  datum,
  style,
}: {
  datum: TimelineDatum;
  style: { left: number };
}) {
  const day = new Date(datum.start).getHours() === 0 ? ` · ${formatDay(datum.start)}` : "";
  return (
    <div
      className="material-overlay pointer-events-none absolute top-1 z-10 w-40 -translate-x-1/2 rounded-lg border border-border/70 p-2.5 shadow-pop"
      style={style}
    >
      <p className="mb-1.5 text-2xs text-muted-foreground">
        {formatClock(datum.start)}
        {day}
      </p>
      {[
        { label: "Download", color: inboundColor, value: datum.inbound },
        { label: "Upload", color: outboundColor, value: datum.outbound },
      ].map((entry) => (
        <p key={entry.label} className="flex items-center justify-between gap-2 text-xs">
          <span className="inline-flex items-center gap-1.5">
            <i className="size-1.5 rounded-full" style={{ background: entry.color }} />
            {entry.label}
          </span>
          <span className="font-medium tabular-nums">{formatBytes(entry.value)}</span>
        </p>
      ))}
    </div>
  );
}

/** Tiny live-rate sparkline for the hero cards. */
export function Sparkline({ values, series }: { values: number[]; series: "inbound" | "outbound" }) {
  const color = series === "inbound" ? inboundColor : outboundColor;
  const id = `spark-${series}`;
  const geometry = useMemo(() => {
    if (values.length < 2) return null;
    const width = 120;
    const height = 40;
    const max = Math.max(...values, 1);
    const step = width / (values.length - 1);
    const points = values.map((value, index): [number, number] => [
      index * step,
      height - (value / max) * (height - 4) - 2,
    ]);
    return {
      width,
      height,
      line: linePath(points),
      area: `${linePath(points)} L${width},${height} L0,${height} Z`,
    };
  }, [values]);

  if (!geometry) return <div className="h-10" />;
  return (
    <svg
      viewBox={`0 0 ${geometry.width} ${geometry.height}`}
      preserveAspectRatio="none"
      className="h-10 w-full"
      aria-hidden
    >
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.25} />
          <stop offset="100%" stopColor={color} stopOpacity={0.02} />
        </linearGradient>
      </defs>
      <path d={geometry.area} fill={`url(#${id})`} />
      <path
        d={geometry.line}
        fill="none"
        stroke={color}
        strokeWidth={1.5}
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

export function formatSeriesRate(bps: number): string {
  return formatRateText(bps);
}
