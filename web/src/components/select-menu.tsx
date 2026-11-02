import { Check, ChevronDown } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

export function SelectMenu<T extends string>({
  label,
  value,
  options,
  onChange,
  emptyValue,
  wide,
}: {
  label: string;
  value: T;
  options: Array<{ value: T; label: string }>;
  onChange: (value: T) => void;
  emptyValue?: T;
  wide?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const listId = useId();
  const current = options.find((option) => option.value === value) ?? options[0];

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={rootRef} className="relative block">
      <span id={`${listId}-label`} className="mb-1 block text-xs text-ink-muted">
        {label}
      </span>
      <button
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={listId}
        aria-labelledby={`${listId}-label`}
        onClick={() => setOpen((currentOpen) => !currentOpen)}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" || event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            setOpen(true);
          }
        }}
        className={`flex h-9 items-center justify-between gap-3 rounded-md border bg-ink-bg px-3 text-sm text-ink-text outline-none hover:bg-ink-raised focus-visible:ring-2 focus-visible:ring-signal/60 ${open ? "border-signal/50" : "border-ink-line"} ${wide ? "w-full" : "min-w-40"}`}
      >
        <span className={value === emptyValue ? "text-ink-muted" : undefined}>{current?.label}</span>
        <ChevronDown className={`size-4 shrink-0 text-ink-muted transition-transform ${open ? "rotate-180" : ""}`} aria-hidden="true" />
      </button>
      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-labelledby={`${listId}-label`}
          className="absolute z-50 mt-1.5 flex max-h-64 w-full min-w-full flex-col gap-1 overflow-auto rounded-lg border border-ink-line bg-ink-panel p-1.5 shadow-[0_12px_32px_rgba(0,0,0,0.45)]"
        >
          {options.map((option) => {
            const selected = option.value === value;
            return (
              <li key={option.value} role="presentation" className="shrink-0">
                <button
                  type="button"
                  role="option"
                  aria-selected={selected}
                  onClick={() => {
                    onChange(option.value);
                    setOpen(false);
                  }}
                  className={`flex h-9 w-full items-center justify-between gap-3 rounded-md px-2.5 text-left text-sm leading-none ${
                    selected ? "bg-signal/15 text-ink-text" : "text-ink-text hover:bg-ink-raised"
                  }`}
                >
                  <span>{option.label}</span>
                  {selected && <Check className="size-4 text-signal" aria-hidden="true" />}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
