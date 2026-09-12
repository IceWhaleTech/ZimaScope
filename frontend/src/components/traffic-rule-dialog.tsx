/**
 * Creates one Traffic Rule from an Explorer row. The dialog is honest about
 * what will happen: a limit drops over-limit packets, a block drops every
 * matching packet, and the direction decides which side of the Device
 * Boundary is affected. Domain rows never reach this dialog because domain
 * matching is not supported.
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
import { useCreateTrafficRule } from "@/hooks/use-data";
import type { RuleAction, RuleDirection } from "@/types";

export interface TrafficRulePreset {
  action: RuleAction;
  label: string;
  match:
    | { kind: "endpoint"; address: string; port?: number }
    | { kind: "application"; application_id: string };
}

const MBPS_TO_BYTES_PER_S = 125_000;

const DIRECTION_OPTIONS = [
  { value: "outbound", label: "Outbound" },
  { value: "inbound", label: "Inbound" },
  { value: "both", label: "Both" },
];

export function TrafficRuleDialog({
  preset,
  onClose,
}: {
  preset: TrafficRulePreset | null;
  onClose: () => void;
}) {
  const createRule = useCreateTrafficRule();
  const [direction, setDirection] = useState<RuleDirection>("outbound");
  const [rateMbps, setRateMbps] = useState("50");

  useEffect(() => {
    if (preset) {
      setDirection("outbound");
      setRateMbps("50");
    }
  }, [preset]);

  const blocking = preset?.action === "block";

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
        match: preset.match,
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
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button
            variant={blocking ? "destructive" : "default"}
            onClick={submit}
            disabled={createRule.isPending}
          >
            {blocking ? "Block traffic" : "Apply limit"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
