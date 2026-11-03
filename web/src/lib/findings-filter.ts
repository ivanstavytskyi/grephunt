import type { Finding, Severity } from "@/api/types";
import { locationLabel } from "@/lib/utils";

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VERDICT_RANK: Record<string, number> = { confirmed: 0, likely: 1, "": 1, false_positive: 2 };

export type FindingsFilterState = {
  severity: Severity | "all";
  category: string;
  query: string;
  tool: string;
};

function rowTitle(finding: Finding): string {
  if (finding.package) return `${finding.package}@${finding.installed_version ?? ""}`;
  return finding.title;
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

export function sortFindingsBySeverity(rows: Finding[]): Finding[] {
  const copy = [...rows];
  copy.sort((left, right) => {
    // After an AI review: confirmed first, likely false positives last.
    const verdict = VERDICT_RANK[left.ai_verdict ?? ""] - VERDICT_RANK[right.ai_verdict ?? ""];
    if (verdict !== 0) return verdict;
    const sev = RANK[left.severity] - RANK[right.severity];
    if (sev !== 0) return sev;
    const exploit = (right.exploitability?.score ?? 0) - (left.exploitability?.score ?? 0);
    if (exploit !== 0) return exploit;
    if (sev !== 0) return sev;
    const pathCmp = (left.location?.path ?? "").localeCompare(right.location?.path ?? "");
    if (pathCmp !== 0) return pathCmp;
    return rowTitle(left).localeCompare(rowTitle(right));
  });
  return copy;
}

export function filterFindings(findings: Finding[], filter: FindingsFilterState): Finding[] {
  const needle = filter.query.trim().toLowerCase();
  const filtered = findings.filter((item) => {
    if (filter.severity !== "all" && item.severity !== filter.severity) return false;
    if (filter.category !== "all" && item.category !== filter.category) return false;
    if (filter.tool !== "all") {
      const names = new Set([item.tool, ...(item.tools ?? [])].map((name) => name.toLowerCase()));
      if (!names.has(filter.tool)) return false;
    }
    if (!needle) return true;
    return searchText(item).includes(needle);
  });
  return sortFindingsBySeverity(filtered);
}

export function describeFindingsFilter(filter: FindingsFilterState, total: number, matched: number): string {
  const parts: string[] = [];
  if (filter.severity !== "all") parts.push(`severity=${filter.severity}`);
  if (filter.category !== "all") parts.push(`category=${filter.category}`);
  if (filter.tool !== "all") parts.push(`tool=${filter.tool}`);
  if (filter.query.trim()) parts.push(`search="${filter.query.trim()}"`);
  if (parts.length === 0) return `${matched} findings (full scan)`;
  return `${matched} of ${total} findings (filters: ${parts.join(", ")})`;
}
