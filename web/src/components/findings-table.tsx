import { useVirtualizer } from "@tanstack/react-virtual";
import { memo, useEffect, useMemo, useRef } from "react";
import type { Finding, Severity } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { filterFindings, type FindingsFilterState } from "@/lib/findings-filter";
import { locationLabel } from "@/lib/utils";
import { ExploitabilityMeter } from "@/components/exploitability";

const ROW_HEIGHT = 64;
const COLUMNS_EDIT = "grid-cols-[2.25rem_5.5rem_6rem_minmax(7rem,11rem)_minmax(0,1fr)_4.5rem_7rem]";
const COLUMNS_VIEW = "grid-cols-[5.5rem_6rem_minmax(7rem,11rem)_minmax(0,1fr)_4.5rem_7rem]";

function rowTitle(finding: Finding): string {
  if (finding.package) return `${finding.package}@${finding.installed_version ?? ""}`;
  return finding.title;
}

function toolLabel(finding: Finding): string {
  const name = (finding.tools ?? []).join("+") || finding.tool;
  return finding.tool_version ? `${name} ${finding.tool_version}` : name;
}

export function findingKey(finding: Finding): string {
  return `${finding.fingerprint}:${finding.correlation_key}`;
}

export const FindingsTable = memo(function FindingsTable({
  findings,
  severity,
  category,
  query,
  tool,
  selected,
  onSelect,
  checked,
  onToggle,
  onToggleVisible,
  editing = false,
}: {
  findings: Finding[];
  severity: Severity | "all";
  category: string;
  query: string;
  tool: string;
  selected: Finding | null;
  onSelect: (finding: Finding) => void;
  checked: Set<string>;
  onToggle: (finding: Finding, value: boolean) => void;
  onToggleVisible: (findings: Finding[], value: boolean) => void;
  /** Selection mode: checkboxes are shown only while the person edits the report. */
  editing?: boolean;
}) {
  const COLUMNS = editing ? COLUMNS_EDIT : COLUMNS_VIEW;
  const parentRef = useRef<HTMLDivElement>(null);

  const filter: FindingsFilterState = useMemo(
    () => ({ severity, category, query, tool }),
    [category, query, severity, tool],
  );

  const rows = useMemo(() => filterFindings(findings, filter), [findings, filter]);
  const allChecked = rows.length > 0 && rows.every((finding) => checked.has(findingKey(finding)));
  const someChecked = rows.some((finding) => checked.has(findingKey(finding)));
  const selectAllRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (selectAllRef.current) selectAllRef.current.indeterminate = someChecked && !allChecked;
  }, [allChecked, someChecked]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 8,
  });

  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-ink-line px-3 py-8 text-sm text-ink-muted">
        No findings match this filter.
      </div>
    );
  }

  return (
    <div ref={parentRef} className="max-h-[640px] overflow-auto rounded-lg border border-ink-line">
      <div className={`sticky top-0 z-10 grid ${COLUMNS} border-b border-ink-line bg-ink-panel text-[11px] uppercase tracking-wide text-ink-muted`}>
        {editing && (
        <div className="flex items-center justify-center">
          <input
            ref={selectAllRef}
            type="checkbox"
            checked={allChecked}
            aria-label="Select all visible findings"
            onChange={(event) => onToggleVisible(rows, event.target.checked)}
            className="size-3.5 accent-signal"
          />
        </div>
        )}
        <div className="px-3 py-2 font-medium">Severity</div>
        <div className="px-3 py-2 font-medium">Category</div>
        <div className="px-3 py-2 font-medium">Location</div>
        <div className="px-3 py-2 font-medium">Finding</div>
        <div className="px-3 py-2 font-medium" title="Estimated exploitability">Exploit</div>
        <div className="px-3 py-2 font-medium">Tool</div>
      </div>
      <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const finding = rows[virtualRow.index];
          const active =
            selected?.fingerprint === finding.fingerprint &&
            selected.correlation_key === finding.correlation_key;
          const where = finding.location ? locationLabel(finding.location) : "";
          const title = rowTitle(finding);
          return (
            <div
              key={`${findingKey(finding)}:${virtualRow.index}`}
              className={`absolute left-0 top-0 grid w-full cursor-pointer items-center overflow-hidden ${COLUMNS} border-b border-ink-line/70 hover:bg-ink-raised ${active ? "bg-ink-raised" : ""} ${checked.has(findingKey(finding)) ? "bg-ink-raised/70" : ""}`}
              style={{ height: ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)` }}
              onClick={() => (editing ? onToggle(finding, !checked.has(findingKey(finding))) : onSelect(finding))}
            >
              {editing && (
              <div
                className="flex items-center justify-center"
                onClick={(event) => event.stopPropagation()}
                onKeyDown={(event) => event.stopPropagation()}
              >
                <input
                  type="checkbox"
                  checked={checked.has(findingKey(finding))}
                  aria-label={`Select ${title}`}
                  onChange={(event) => onToggle(finding, event.target.checked)}
                  className="size-3.5 accent-signal"
                />
              </div>
              )}
              <div className="px-3 py-2.5">
                <Badge tone={finding.severity}>{finding.severity}</Badge>
              </div>
              <div className="px-3 py-2.5 text-sm">{finding.category}</div>
              <div className="min-w-0 px-3 py-2.5 font-mono text-xs leading-4" title={where}>
                <span className="line-clamp-2 break-all">{where}</span>
              </div>
              <div className="min-w-0 px-3 py-2.5 text-sm leading-5">
                <p className="flex min-w-0 items-center gap-1.5" title={finding.ai_reason ? `${title}\nAI: ${finding.ai_reason}` : title}>
                  {finding.ai_verdict && <VerdictTag verdict={finding.ai_verdict} />}
                  <span className={`truncate ${finding.ai_verdict === "false_positive" ? "text-ink-muted line-through decoration-ink-muted/50" : ""}`}>{title}</span>
                </p>
                {(finding.kev || typeof finding.epss === "number" || finding.secret_live === true) && (
                  <p className="flex items-center gap-1.5 font-mono text-[10px] leading-4">
                    {finding.kev && <span className="rounded bg-rose-500/20 px-1 text-rose-100" title="CISA Known Exploited Vulnerabilities">KEV</span>}
                    {typeof finding.epss === "number" && (
                      <span className="text-ink-muted" title="EPSS: probability of exploitation in the next 30 days">
                        EPSS {(finding.epss * 100).toFixed(1)}%
                      </span>
                    )}
                    {finding.secret_live === true && <span className="rounded bg-rose-500/20 px-1 text-rose-100">live key</span>}
                  </p>
                )}
                {finding.context?.routes?.[0] && (
                  <p className="truncate font-mono text-[11px] leading-4 text-ink-muted" title="Route that reaches this code (project map)">
                    {finding.context.routes[0].label}
                    {finding.context.database?.dynamic && <span className="ml-1.5 text-rose-300">· query built from variables</span>}
                  </p>
                )}
              </div>
              <div className="flex px-3 py-2">
                {finding.exploitability ? <ExploitabilityMeter exploitability={finding.exploitability} /> : <span className="text-xs text-ink-muted">—</span>}
              </div>
              <div className="px-3 py-2.5 font-mono text-xs text-ink-muted">{toolLabel(finding)}</div>
            </div>
          );
        })}
      </div>
      <p className="border-t border-ink-line px-3 py-2 text-xs text-ink-muted">
        {rows.length} findings. Full message opens in the panel on the right.
      </p>
    </div>
  );
});
const VERDICT: Record<string, { text: string; tone: string }> = {
  confirmed: { text: "AI ✓", tone: "bg-rose-500/15 text-rose-200" },
  likely: { text: "AI ?", tone: "bg-amber-400/15 text-amber-100" },
  false_positive: { text: "AI ✗", tone: "bg-zinc-500/20 text-zinc-300" },
};

function VerdictTag({ verdict }: { verdict: string }) {
  const item = VERDICT[verdict];
  if (!item) return null;
  const meaning = verdict === "confirmed" ? "confirmed by AI review" : verdict === "likely" ? "AI review: likely real, input source not shown" : "AI review: likely a false positive";
  return (
    <span className={`shrink-0 rounded px-1 font-mono text-[10px] leading-4 ${item.tone}`} title={meaning}>
      {item.text}
    </span>
  );
}
