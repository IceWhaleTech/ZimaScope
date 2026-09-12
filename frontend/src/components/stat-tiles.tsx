/**
 * Detail-panel building blocks: stat tiles and definition rows, mirroring
 * macOS System Settings grouped lists (hairline-separated rows).
 */

import { cn } from "@/lib/utils";

export function StatTiles({ tiles }: { tiles: Array<{ label: string; value: string }> }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {tiles.map((tile) => (
        <div key={tile.label} className="rounded-lg bg-muted/60 px-2.5 py-2">
          <span className="block text-2xs text-muted-foreground">{tile.label}</span>
          <strong className="mt-0.5 block truncate text-sm font-semibold tabular-nums">
            {tile.value}
          </strong>
        </div>
      ))}
    </div>
  );
}

export function DefList({
  rows,
  compact,
}: {
  rows: Array<{ label: string; value: React.ReactNode; wrap?: boolean }>;
  compact?: boolean;
}) {
  return (
    <dl className={cn("flex flex-col", compact && "text-xs")}>
      {rows.map((row) => (
        <div
          key={row.label}
          className="flex items-baseline justify-between gap-4 border-b border-border/60 py-1.5 last:border-b-0"
        >
          <dt className="shrink-0 text-xs text-muted-foreground">{row.label}</dt>
          <dd className={cn("min-w-0 text-right text-xs", !row.wrap && "truncate")}>{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function PanelSection({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-2.5">
      <div>
        <h3 className="text-xs font-semibold">{title}</h3>
        {subtitle && <p className="text-2xs text-muted-foreground">{subtitle}</p>}
      </div>
      {children}
    </section>
  );
}
