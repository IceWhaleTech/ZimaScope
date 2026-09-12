/** Empty-state block used by tables and lists. */

import type { LucideIcon } from "lucide-react";

export function EmptyState({
  icon: Icon,
  title,
  message,
  action,
}: {
  icon: LucideIcon;
  title: string;
  message: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-6 py-12 text-center">
      <div className="mb-2 grid size-11 place-items-center rounded-full bg-muted text-muted-foreground">
        <Icon className="size-5" strokeWidth={1.7} />
      </div>
      <h3 className="text-xs font-semibold">{title}</h3>
      <p className="max-w-sm text-xs text-muted-foreground">{message}</p>
      {action}
    </div>
  );
}
