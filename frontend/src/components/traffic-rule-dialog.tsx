/**
 * Creates one Traffic Rule from an Explorer row. The dialog is honest about
 * what will happen: a limit drops over-limit packets, a block drops every
 * matching packet, and the direction decides which side of the Device
 * Boundary is affected. The selector is resolved through the preflight before
 * confirmation, so unresolved resources are disclosed instead of silently
 * enforced. Domain rows never reach this dialog because domain matching is
 * not supported.
 */

import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Segmented } from "@/components/segmented";
import { useCreateTrafficRule, useResolveTrafficRule } from "@/hooks/use-data";
import type {
  ResolvedTarget,
  RuleAction,
  RuleDirection,
  TrafficRuleSelector,
} from "@/types";

export interface TrafficRulePreset {
  action: RuleAction;
  label: string;
  selector: TrafficRuleSelector;
}

const MBPS_TO_BYTES_PER_S = 125_000;

const DIRECTION_OPTIONS = [
  { value: "outbound", label: "Upload" },
  { value: "inbound", label: "Download" },
  { value: "both", label: "Both" },
];

function targetLabel(target: ResolvedTarget): string {
  switch (target.kind) {
    case "endpoint":
      return target.port ? `${target.address}:${target.port}` : (target.address ?? "endpoint");
    case "cidr":
      return `${target.address}/${target.prefix_len}`;
    case "application_comm":
      return target.comm ?? "process";
    default:
      return `cgroup ${target.cgroup_id}`;
  }
}

export function TrafficRuleDialog({
  preset,
  onClose,
}: {
  preset: TrafficRulePreset | null;
  onClose: () => void;
}) {
  const createRule = useCreateTrafficRule();
  const {
    mutate: resolve,
    reset: resetResolve,
    data: resolution,
    error: resolveError,
    isPending: resolving,
  } = useResolveTrafficRule();
  const [direction, setDirection] = useState<RuleDirection>("outbound");
  const [rateMbps, setRateMbps] = useState("50");

  useEffect(() => {
    if (preset) {
      setDirection("outbound");
      setRateMbps("50");
    } else {
      resetResolve();
    }
  }, [preset, resetResolve]);

  useEffect(() => {
    if (!preset) return;
    resolve({ direction, selector: preset.selector });
  }, [preset, direction, resolve]);

  const blocking = preset?.action === "block";
  const targets = resolution?.targets ?? [];
  const unresolved = resolution?.coverage === "unresolved";

  const submit = () => {
    if (!preset) return;
    const rate = Math.round(Number(rateMbps) * MBPS_TO_BYTES_PER_S);
    if (!blocking && (!Number.isFinite(rate) || rate <= 0)) {
      toast.error("Enter a rate above zero");
      return;
    }

    createRule.mutate(
      {
        action: preset.action,
        direction,
        selector: preset.selector,
        rate_bytes_per_s: blocking ? undefined : rate,
      },
      {
        onSuccess: (rule) => {
          toast.success(blocking ? `Blocking ${preset.label}` : `Limiting ${preset.label}`, {
            description:
              rule.state === "active"
                ? "Enforced at the device boundary."
                : rule.state_reason ?? "Stored, but not enforced right now.",
          });
          onClose();
        },
        onError: (error) =>
          toast.error("Could not create the rule", {
            description: error instanceof Error ? error.message : undefined,
          }),
      },
    );
  };

  return (
    <Dialog
      open={preset !== null}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{blocking ? "Block traffic" : "Rate limit"}</DialogTitle>
          <DialogDescription>
            {preset?.label} —{" "}
            {blocking
              ? "every matching packet is dropped at the device boundary."
              : "matching traffic is dropped above the configured rate. TCP backs off through congestion control."}
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <span className="text-2xs font-medium text-muted-foreground">Direction</span>
            <Segmented
              options={DIRECTION_OPTIONS}
              value={direction}
              onChange={(value) => setDirection(value as RuleDirection)}
              ariaLabel="Traffic direction"
            />
          </div>

          {!blocking && (
            <label className="grid gap-1.5">
              <span className="text-2xs font-medium text-muted-foreground">Rate (Mbps)</span>
              <Input
                inputMode="decimal"
                value={rateMbps}
                onChange={(event) => setRateMbps(event.target.value)}
                className="font-mono"
              />
            </label>
          )}

          <div className="grid gap-1 text-2xs text-muted-foreground">
            {resolving && <p>Resolving what this matches…</p>}
            {resolveError && (
              <p className="text-destructive">
                {resolveError instanceof Error
                  ? resolveError.message
                  : "This selector cannot be enforced"}
              </p>
            )}
            {resolution?.coverage === "complete" && (
              <>
                <p>
                  Matches {targets.length} kernel target{targets.length === 1 ? "" : "s"}
                  {resolution.plan === "resolved" ? ", re-resolved as evidence changes" : ""}.
                </p>
                <p className="truncate font-mono">
                  {targets
                    .slice(0, 3)
                    .map(targetLabel)
                    .join(", ")}
                  {targets.length > 3 ? ` +${targets.length - 3} more` : ""}
                </p>
              </>
            )}
            {unresolved && (
              <p className="text-amber-500">
                No matching resources right now
                {resolution.reason ? `: ${resolution.reason}` : ""}. The rule is stored but stays
                inactive until evidence appears.
              </p>
            )}
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={blocking ? "destructive" : "default"}
            onClick={submit}
            disabled={createRule.isPending || resolveError !== null}
          >
            {blocking ? "Block traffic" : "Apply limit"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
