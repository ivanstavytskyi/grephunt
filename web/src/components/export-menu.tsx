import { ChevronDown, Download } from "lucide-react";
import { useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { EXPORT_FORMATS, type ExportFormat } from "@/lib/scan-export";

/**
 * "Export" menu button (WAI-ARIA APG menu button pattern): Enter, Space or ArrowDown opens it,
 * arrow keys move between formats, Escape closes and returns focus to the button.
 */
export function ExportMenu({
  onExport,
  disabled = false,
  title = "Download the report",
  iconOnly = false,
}: {
  onExport: (format: ExportFormat) => void;
  disabled?: boolean;
  title?: string;
  iconOnly?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const menuId = useId();
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const items = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    if (!open) return;
    items.current[active]?.focus();
  }, [open, active]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener("pointerdown", onPointer);
    return () => document.removeEventListener("pointerdown", onPointer);
  }, [open]);

  const close = (focusButton = true) => {
    setOpen(false);
    if (focusButton) button.current?.focus();
  };

  const choose = (format: ExportFormat) => {
    close();
    onExport(format);
  };

  const onButtonKey = (event: KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      setActive(event.key === "ArrowUp" ? EXPORT_FORMATS.length - 1 : 0);
      setOpen(true);
    }
  };

  const onMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const last = EXPORT_FORMATS.length - 1;
    if (event.key === "Escape") {
      event.preventDefault();
      close();
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      setActive((index) => (index >= last ? 0 : index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActive((index) => (index <= 0 ? last : index - 1));
    } else if (event.key === "Home") {
      event.preventDefault();
      setActive(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActive(last);
    } else if (event.key === "Tab") {
      close(false);
    }
  };

  return (
    <div ref={root} className="relative inline-flex">
      <button
        ref={button}
        type="button"
        disabled={disabled}
        title={title}
        aria-label={iconOnly ? "Export report" : undefined}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => {
          setActive(0);
          setOpen((value) => !value);
        }}
        onKeyDown={onButtonKey}
        className={
          iconOnly
            ? "flex size-9 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:bg-ink-raised hover:text-ink-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ink-muted/70 disabled:cursor-not-allowed disabled:opacity-50"
            : "inline-flex h-9 shrink-0 items-center justify-center gap-2 rounded-md border border-ink-line bg-ink-panel px-3.5 text-sm font-medium text-ink-text transition-colors hover:border-ink-muted/50 hover:bg-ink-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ink-muted/70 disabled:cursor-not-allowed disabled:opacity-50"
        }
      >
        <Download className="size-4 shrink-0 text-ink-muted" aria-hidden="true" />
        {!iconOnly && (
          <>
            Export
            <ChevronDown className="size-3.5 shrink-0 text-ink-muted" aria-hidden="true" />
          </>
        )}
      </button>
      {open && (
        <div
          id={menuId}
          role="menu"
          aria-label="Export format"
          onKeyDown={onMenuKey}
          className="absolute right-0 top-full z-50 mt-1 w-64 overflow-hidden rounded-md border border-ink-line bg-ink-panel py-1 shadow-lg shadow-black/40"
        >
          {EXPORT_FORMATS.map((item, index) => (
            <button
              key={item.format}
              ref={(element) => {
                items.current[index] = element;
              }}
              type="button"
              role="menuitem"
              tabIndex={index === active ? 0 : -1}
              onClick={() => choose(item.format)}
              onMouseEnter={() => setActive(index)}
              className="flex w-full flex-col items-start px-3 py-2 text-left outline-none hover:bg-ink-raised focus:bg-ink-raised"
            >
              <span className="text-sm text-ink-text">{item.label}</span>
              <span className="text-xs text-ink-muted">{item.hint}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
