import type { HTMLAttributes } from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/api/types";

const tones: Record<Severity, string> = {
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  medium: "bg-amber-400/15 text-amber-200 ring-amber-400/30",
  low: "bg-zinc-500/15 text-zinc-300 ring-zinc-500/30",
  info: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
};

export function Badge({
  className,
  tone = "info",
  ...props
}: HTMLAttributes<HTMLSpanElement> & { tone?: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide ring-1 ring-inset",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}
