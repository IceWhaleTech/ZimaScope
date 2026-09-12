/**
 * iOS-style segmented control over Radix ToggleGroup. The white thumb sits on
 * a recessed track; selection is instant (no sliding thumb to get in the way
 * of quick repeated taps).
 */

import { cn } from "@/lib/utils";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";

export interface SegmentOption {
  value: string;
  label: string;
}

export function Segmented({
  options,
  value,
  onChange,
  ariaLabel,
  className,
  disabled,
}: {
  options: SegmentOption[];
  value: string;
  onChange: (value: string) => void;
  ariaLabel?: string;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <ToggleGroup
      type="single"
      spacing={1}
      value={value}
      disabled={disabled}
      onValueChange={(next) => {
        if (next) onChange(next);
      }}
      aria-label={ariaLabel}
      className={cn(
        "inline-flex items-center gap-0.5 rounded-md bg-secondary p-0.5",
        className,
      )}
    >
      {options.map((option) => (
        <ToggleGroupItem
          key={option.value}
          value={option.value}
          className={cn(
            "h-6 rounded-[5px] border-0 bg-transparent px-2.5 text-xs font-medium text-muted-foreground shadow-none transition-colors",
            "hover:bg-transparent hover:text-foreground",
            "data-[state=on]:bg-card data-[state=on]:text-foreground data-[state=on]:shadow-xs",
            "dark:data-[state=on]:bg-card dark:data-[state=on]:shadow-none dark:data-[state=on]:ring-1 dark:data-[state=on]:ring-border/60",
          )}
        >
          {option.label}
        </ToggleGroupItem>
      ))}
    </ToggleGroup>
  );
}
