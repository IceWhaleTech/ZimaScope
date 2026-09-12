/**
 * Export task list: created on demand, downloadable until they expire and
 * deletable at any time. Used by Settings; the Explorer offers the same
 * download through a toast action.
 */

import { Download, FileJson, FileSpreadsheet, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useDeleteExport, useExports } from "@/hooks/use-data";
import { downloadExport } from "@/lib/download";
import { formatBytes, formatNumber, relativeTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ExportTask } from "@/types";

export function ExportTasks({ limit = 4, className }: { limit?: number; className?: string }) {
  const exportsQuery = useExports();
  const deleteExport = useDeleteExport();
  const tasks = exportsQuery.data?.slice(0, limit) ?? [];

  if (exportsQuery.isLoading) {
    return (
      <div className={cn("flex flex-col gap-2 py-1", className)}>
        {Array.from({ length: 2 }, (_, index) => (
          <Skeleton key={index} className="h-9" />
        ))}
      </div>
    );
  }

  if (!tasks.length) {
    return (
      <p className={cn("py-2.5 text-2xs text-muted-foreground", className)}>
        No exports yet. JSON keeps Flow metadata, domain evidence and IP profiles together; CSV is
        Flow records only.
      </p>
    );
  }

  return (
    <ul className={cn("flex flex-col", className)}>
      {tasks.map((task) => (
        <ExportRow
          key={task.id}
          task={task}
          deleting={deleteExport.isPending}
          onDelete={() =>
            deleteExport.mutate(task.id, { onSuccess: () => toast.success("Export deleted") })
          }
        />
      ))}
    </ul>
  );
}

function ExportRow({
  task,
  deleting,
  onDelete,
}: {
  task: ExportTask;
  deleting: boolean;
  onDelete: () => void;
}) {
  const expired = task.status === "expired";
  return (
    <li className="flex items-center gap-2.5 border-b border-border/60 py-2 last:border-0">
      <span className="grid size-7 shrink-0 place-items-center rounded-md bg-secondary text-secondary-foreground">
        {task.format === "csv" ? <FileSpreadsheet className="size-3.5" /> : <FileJson className="size-3.5" />}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <strong className="text-xs font-medium uppercase">{task.format}</strong>
          {task.range && <span className="text-2xs text-muted-foreground">{task.range}</span>}
          {task.truncated && (
            <span className="rounded-full bg-warning/15 px-1.5 py-px text-[10px] font-medium text-warning">
              truncated
            </span>
          )}
          {expired && (
            <span className="rounded-full bg-muted px-1.5 py-px text-[10px] font-medium text-muted-foreground">
              expired
            </span>
          )}
        </span>
        <small className="mt-0.5 block truncate text-2xs text-muted-foreground">
          {formatNumber(task.record_count)} records · {formatBytes(task.size_bytes)} ·{" "}
          {relativeTime(task.created_at)}
          {task.truncated ? " · first 10,000 records only" : ""}
        </small>
      </span>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label="Download export"
        disabled={expired}
        title={expired ? "Export content expired" : "Download"}
        onClick={() => downloadExport(task.id)}
      >
        <Download className="size-3.5" />
      </Button>
      <Button
        variant="ghost"
        size="icon-sm"
        aria-label="Delete export"
        disabled={deleting}
        onClick={onDelete}
      >
        <Trash2 className="size-3.5" />
      </Button>
    </li>
  );
}
