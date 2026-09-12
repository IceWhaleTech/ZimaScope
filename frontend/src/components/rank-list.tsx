/**
 * Ranked list with a proportion bar — the "top N" pattern used across the
 * Overview. Ratios are encoded by bar width in a single accent color.
 */

import { Link } from "react-router";
import { cn } from "@/lib/utils";

export interface RankItem {
  label: string;
  sub?: string;
  value: string;
  ratio: number;
  href?: string;
  leading?: React.ReactNode;
}

export function RankList({ items, emptyText }: { items: RankItem[]; emptyText: string }) {
  if (!items.length) {
    return <p className="py-2 text-xs text-muted-foreground">{emptyText}</p>;
  }
  return (
    <ol className="flex flex-col">
      {items.map((item, index) => {
        const row = (
          <>
            <span className="w-4 shrink-0 pt-0.5 text-2xs tabular-nums text-muted-foreground">
              {index + 1}
            </span>
            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-1.5">
                {item.leading}
                <span className="truncate text-xs font-medium">{item.label}</span>
              </span>
              {item.sub && <span className="block truncate text-2xs text-muted-foreground">{item.sub}</span>}
            </span>
            <span className="pt-0.5 text-xs tabular-nums text-muted-foreground">{item.value}</span>
            <span className="absolute inset-x-0 bottom-0 h-px bg-border/60" />
            <span
              className="absolute bottom-0 left-0 h-px bg-primary/50"
              style={{ width: `${Math.max(2, Math.min(100, item.ratio * 100)).toFixed(1)}%` }}
            />
          </>
        );
        const className =
          "relative flex items-start gap-2.5 overflow-hidden py-1.5 pr-1 pl-0.5 transition-colors";
        return (
          <li key={`${item.label}-${index}`} className="list-none">
            {item.href ? (
              <Link to={item.href} className={cn(className, "rounded-md hover:bg-accent")}>
                {row}
              </Link>
            ) : (
              <div className={className}>{row}</div>
            )}
          </li>
        );
      })}
    </ol>
  );
}
