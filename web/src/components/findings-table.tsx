import { useVirtualizer } from "@tanstack/react-virtual";
import { memo, useMemo, useRef } from "react";
import type { Finding, Severity } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { locationLabel } from "@/lib/utils";

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const ROW_HEIGHT = 52;

function rowTitle(finding: Finding): string {
  if (finding.package) return `${finding.package}@${finding.installed_version ?? ""}`;
  return finding.title;
}

function toolLabel(finding: Finding): string {
  const name = (finding.tools ?? []).join("+") || finding.tool;
  return finding.tool_version ? `${name} ${finding.tool_version}` : name;
}

function rowKey(finding: Finding): string {
  return `${finding.fingerprint}:${finding.correlation_key}`;
}

function searchText(finding: Finding): string {
  const where = finding.location ? locationLabel(finding.location) : "";
  return [
    finding.title,
    finding.rule_id,
    where,
    finding.package,
    finding.message,
    finding.description,
    ...(finding.cve ?? []),
    ...(finding.cwe ?? []),
  ]
    .filter((value): value is string => typeof value === "string" && value.length > 0)
    .join("\n")
    .toLowerCase();
}

function sortFindings(rows: Finding[]): Finding[] {
  const copy = [...rows];
  copy.sort((left, right) => {
    const sev = RANK[left.severity] - RANK[right.severity];
    if (sev !== 0) return sev;
    return rowTitle(left).localeCompare(rowTitle(right));
  });
  return copy;
}

export const FindingsTable = memo(function FindingsTable({
  findings,
  severity,
  category,
  query,
  tool,
  selected,
  onSelect,
}: {
  findings: Finding[];
  severity: Severity | "all";
  category: string;
  query: string;
  tool: string;
  selected: Finding | null;
  onSelect: (finding: Finding) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const needle = query.trim().toLowerCase();

  const searchIndex = useMemo(
    () => new Map(findings.map((item) => [item, searchText(item)] as const)),
    [findings],
  );

  const rows = useMemo(() => {
    const filtered = findings.filter((item) => {
      if (severity !== "all" && item.severity !== severity) return false;
      if (category !== "all" && item.category !== category) return false;
      if (tool !== "all") {
        const names = new Set([item.tool, ...(item.tools ?? [])].map((name) => name.toLowerCase()));
        if (!names.has(tool)) return false;
      }
      if (!needle) return true;
      return (searchIndex.get(item) ?? "").includes(needle);
    });
    return sortFindings(filtered);
  }, [category, findings, needle, searchIndex, severity, tool]);

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
      <div className="sticky top-0 z-10 grid grid-cols-[5.5rem_6rem_minmax(7rem,11rem)_minmax(0,1fr)_7rem] border-b border-ink-line bg-ink-panel text-[11px] uppercase tracking-wide text-ink-muted">
        <div className="px-3 py-2 font-medium">Severity</div>
        <div className="px-3 py-2 font-medium">Category</div>
        <div className="px-3 py-2 font-medium">Location</div>
        <div className="px-3 py-2 font-medium">Finding</div>
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
              key={rowKey(finding)}
              className={`absolute left-0 top-0 grid w-full cursor-pointer grid-cols-[5.5rem_6rem_minmax(7rem,11rem)_minmax(0,1fr)_7rem] border-b border-ink-line/70 hover:bg-ink-raised ${active ? "bg-ink-raised" : ""}`}
              style={{ height: ROW_HEIGHT, transform: `translateY(${virtualRow.start}px)` }}
              role="button"
              tabIndex={0}
              aria-label={`${finding.severity} ${title}, ${where || "no location"}, ${toolLabel(finding)}`}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onSelect(finding);
                }
              }}
              onClick={() => onSelect(finding)}
            >
              <div className="px-3 py-2.5 align-top">
                <Badge tone={finding.severity}>{finding.severity}</Badge>
              </div>
              <div className="px-3 py-2.5 text-sm">{finding.category}</div>
              <div className="px-3 py-2.5 font-mono text-xs leading-5 break-all">{where}</div>
              <div className="min-w-0 px-3 py-2.5 text-sm leading-5">
                <p className="truncate" title={title}>
                  {title}
                </p>
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