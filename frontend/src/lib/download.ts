import { exportContentUrl } from "@/api";

/** Triggers a browser download for a completed export task. */
export function downloadExport(id: string): void {
  const anchor = document.createElement("a");
  anchor.href = exportContentUrl(id);
  anchor.download = "";
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
}
