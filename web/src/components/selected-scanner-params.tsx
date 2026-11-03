import { ChevronDown } from "lucide-react";
import type { ToolInfo } from "@/api/types";
import { ScannerParamForm } from "@/components/scanner-param-form";
import { paramsDifferFromDefaults, summarizeToolParams, type ToolParamsState } from "@/lib/scanner-params";

export function SelectedScannerParams({
  tools,
  selected,
  params,
  onParamsChange,
  expanded,
  onExpandedChange,
}: {
  tools: ToolInfo[];
  selected: string[];
  params: ToolParamsState;
  onParamsChange: (tool: string, values: Record<string, unknown>) => void;
  expanded: string | null;
  onExpandedChange: (tool: string | null) => void;
}) {
  const rows = selected
    .map((name) => tools.find((tool) => tool.name === name))
    .filter((tool): tool is ToolInfo => Boolean(tool?.parameters?.length));

  if (rows.length === 0) return null;

  return (
    <fieldset className="mt-6">
      <legend className="mb-2 text-sm">Selected scanners</legend>
      <p className="mb-3 text-xs leading-5 text-ink-muted">
        Options for this run only. Values are saved with the scan for later reports.
      </p>
      <ul className="space-y-2">
        {rows.map((tool) => {
          const values = params[tool.name] ?? {};
          const summary = summarizeToolParams(tool, values);
          const modified = paramsDifferFromDefaults(tool, values);
          const open = expanded === tool.name;
          return (
            <li key={tool.name} className="overflow-hidden rounded-md border border-ink-line bg-ink-panel/40">
              <button
                type="button"
                aria-expanded={open}
                onClick={() => onExpandedChange(open ? null : tool.name)}
                className="flex w-full items-center gap-3 px-3 py-2.5 text-left hover:bg-ink-raised/40"
              >
                <span className="min-w-0 flex-1">
                  <span className="font-mono text-sm">{tool.name}</span>
                  {summary && <span className="mt-0.5 block truncate text-xs text-ink-muted">{summary}</span>}
                </span>
                {modified && (
                  <span className="shrink-0 rounded border border-signal/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-signal">
                    changed
                  </span>
                )}
                <ChevronDown
                  className={`size-4 shrink-0 text-ink-muted transition-transform ${open ? "rotate-180" : ""}`}
                  aria-hidden="true"
                />
              </button>
              {open && (
                <div className="border-t border-ink-line bg-ink-panel/80 p-3">
                  <ScannerParamForm
                    specs={tool.parameters ?? []}
                    values={values}
                    onChange={(next) => onParamsChange(tool.name, next)}
                  />
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </fieldset>
  );
}
