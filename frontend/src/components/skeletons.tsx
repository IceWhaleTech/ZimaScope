/** Quiet placeholder blocks — static, no shimmer sweep. */

import { Skeleton as UiSkeleton } from "@/components/ui/skeleton";
import { TableCell, TableRow } from "@/components/ui/table";

export function Skeleton({ className }: { className?: string }) {
  return <UiSkeleton className={className} />;
}

export function SkeletonRows({ rows = 3, className }: { rows?: number; className?: string }) {
  return (
    <div className={className}>
      {Array.from({ length: rows }, (_, index) => (
        <UiSkeleton key={index} className="mb-2 h-9 last:mb-0" />
      ))}
    </div>
  );
}

/** Table-shaped skeleton. Renders bare `<tr>`s so callers place it inside an
    existing `<tbody>`; nesting a second tbody is invalid DOM and React 19
    treats it as an error. */
export function TableSkeleton({ rows = 6, columns = 6 }: { rows?: number; columns?: number }) {
  return (
    <>
      {Array.from({ length: rows }, (_, row) => (
        <TableRow key={row} className="hover:bg-transparent">
          {Array.from({ length: columns }, (_, column) => (
            <TableCell key={column}>
              <UiSkeleton className="h-4 w-full max-w-32" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
}
