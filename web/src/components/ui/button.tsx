import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import type { ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-signal/70 disabled:pointer-events-none disabled:opacity-40",
  {
    variants: {
      variant: {
        default: "bg-signal text-ink-bg hover:bg-signal/90",
        ghost: "hover:bg-ink-raised text-ink-text",
        outline: "border border-ink-line bg-transparent hover:bg-ink-raised",
      },
      size: {
        default: "h-9 px-3",
        sm: "h-8 px-2.5 text-xs",
        lg: "h-10 px-4",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

/*
 * Toolbar hierarchy: one primary action (light fill, shadcn/ui dark-theme convention),
 * everything else neutral. AI actions are marked by the lime brand icon only, so the bright
 * accent covers a few pixels instead of whole outlines.
 */
const base =
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-ink-bg disabled:cursor-not-allowed disabled:opacity-50";
export const primaryButton = `${base} bg-ink-text text-ink-bg hover:bg-white focus-visible:ring-ink-text/70`;
export const secondaryButton = `${base} border border-ink-line bg-ink-panel text-ink-text hover:border-ink-muted/50 hover:bg-ink-raised focus-visible:ring-ink-muted/70`;
export const aiButton = secondaryButton;
export const aiIcon = "text-ink-muted";

export function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot : "button";
  return <Comp className={cn(buttonVariants({ variant, size }), className)} {...props} />;
}
