import type { InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "flex h-9 w-full rounded-md border border-ink-line bg-ink-bg px-3 text-sm text-ink-text outline-none placeholder:text-ink-muted focus-visible:ring-2 focus-visible:ring-signal/60",
        className,
      )}
      {...props}
    />
  );
}
