import type { Finding, ScanSummary } from "@/api/types";
import { describeFindingsFilter, type FindingsFilterState } from "@/lib/findings-filter";

export type AiReportChatMessage = {
  role: "user" | "assistant";
  content: string;
};
import { locationLabel } from "@/lib/utils";

const SNIPPET_MAX = 2400;
const MESSAGE_MAX = 1200;

function escapeMdInline(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/`/g, "\\`");
}

function fenceCode(text: string, lang: string): string {
  const body = text.replace(/\r\n/g, "\n");
  const fence = body.includes("```") ? "````" : "```";
  return `${fence}${lang}\n${body}\n${fence}`;
}

function truncate(value: string | null | undefined, max: number): string {
  if (!value) return "";
  const normalized = value.replace(/\r\n/g, "\n").trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 3)}...`;
}

function findingTitle(finding: Finding): string {
  if (finding.package) {
    const ver = finding.installed_version ? `@${finding.installed_version}` : "";
    return `${finding.package}${ver}`;
  }
  return finding.title;
}

function formatFindingBlock(index: number, finding: Finding): string {
  const id = `F-${String(index).padStart(3, "0")}`;
  const where = finding.location ? locationLabel(finding.location) : "";
  const tools = (finding.tools?.length ? finding.tools : [finding.tool]).filter(Boolean).join("+");
  const toolLine = finding.tool_version ? `${tools} (${finding.tool_version})` : tools;
  const refs: string[] = [];
  if (finding.cve?.length) refs.push(`CVE: ${finding.cve.join(", ")}`);
  if (finding.cwe?.length) refs.push(`CWE: ${finding.cwe.join(", ")}`);
  if (finding.owasp?.length) refs.push(`OWASP: ${finding.owasp.join(", ")}`);
  const dep =
    finding.fixed_version != null && finding.fixed_version !== ""
      ? `Fixed in: ${finding.fixed_version}`
      : "";

  const lines = [
    `### ${id} · ${finding.severity} · ${finding.category}`,
    "",
    `**Title:** ${findingTitle(finding)}`,
    `**Tool:** ${escapeMdInline(toolLine)} · rule \`${escapeMdInline(finding.rule_id || "—")}\``,
  ];
  if (where) lines.push(`**Location:** \`${escapeMdInline(where)}\``);
  if (refs.length) lines.push(`**Refs:** ${refs.join(" · ")}`);
  if (dep) lines.push(`**Dependency:** ${dep}`);
  const message = truncate(finding.message || finding.description, MESSAGE_MAX);
  if (message) {
    lines.push("", "**Message:**", message);
  }
  const snippet = truncate(finding.snippet, SNIPPET_MAX);
  if (snippet) {
    lines.push("", "**Snippet:**", fenceCode(snippet, finding.location?.path?.split(".").pop() ?? ""));
  }
  if (finding.help_uri) lines.push("", `**Help:** ${finding.help_uri}`);
  return lines.join("\n");
}

function severityCounts(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of findings) {
    const key = item.severity || "info";
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

function categoryCounts(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of findings) {
    const key = item.category || "unknown";
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

function metadataSection(scan: ScanSummary, scopeLine: string): string {
  const scanners = scan.tasks?.map((task) => task.tool).filter(Boolean).join(", ") || "—";
  const lines = [
    "## Scan metadata",
    "",
    "| Field | Value |",
    "| --- | --- |",
    `| Scan ID | \`${scan.id}\` |`,
    `| Target | ${scan.target_label || "—"} |`,
    `| Path | \`${scan.target_path || "—"}\` |`,
    `| Status | ${scan.status}${scan.partial ? " (partial)" : ""} |`,
    `| Created | ${scan.created_at ?? "—"} |`,
    `| Finished | ${scan.finished_at ?? "—"} |`,
    `| Duration | ${scan.duration_sec != null ? `${scan.duration_sec}s` : "—"} |`,
    `| Scanners | ${scanners} |`,
    `| Raw / excluded | ${scan.raw_total ?? 0} / ${scan.excluded ?? 0} |`,
    `| Export scope | ${scopeLine} |`,
  ];
  if (scan.source_repo_url) {
    lines.push(`| Source repo | ${scan.source_repo_url} |`);
    if (scan.source_ref) lines.push(`| Source ref | \`${scan.source_ref}\` |`);
  }
  return lines.join("\n");
}

function summarySection(findings: Finding[]): string {
  const bySev = severityCounts(findings);
  const byCat = categoryCounts(findings);
  const sevOrder = ["critical", "high", "medium", "low", "info"];
  const sevLines = sevOrder
    .filter((s) => (bySev[s] ?? 0) > 0)
    .map((s) => `- **${s}:** ${bySev[s]}`);
  const catLines = Object.entries(byCat)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => `- **${cat}:** ${count}`);
  return [
    "## Summary",
    "",
    "**By severity**",
    ...(sevLines.length ? sevLines : ["- (none)"]),
    "",
    "**By category**",
    ...(catLines.length ? catLines : ["- (none)"]),
  ].join("\n");
}

function findingsCatalog(findings: Finding[]): string {
  const blocks = findings.map((item, index) => formatFindingBlock(index + 1, item));
  return ["## Findings catalog", "", "Stable IDs (`F-001`, …) for reference in follow-up analysis.", "", ...blocks].join(
    "\n\n",
  );
}

function chatSection(messages: AiReportChatMessage[]): string {
  if (!messages.length) return "";
  const parts = ["## Follow-up conversation", ""];
  for (const message of messages) {
    const label = message.role === "user" ? "User" : "Assistant";
    parts.push(`### ${label}`, "", message.content.trim(), "");
  }
  return parts.join("\n");
}

export type ScanExportOptions = {
  scan: ScanSummary;
  findings: Finding[];
  filter?: FindingsFilterState;
  totalFindings?: number;
  aiReport?: string;
  chatMessages?: AiReportChatMessage[];
};

export function buildScanExportMarkdown(options: ScanExportOptions): string {
  const { scan, findings, filter, totalFindings, aiReport, chatMessages } = options;
  const total = totalFindings ?? findings.length;
  const scopeLine = filter
    ? describeFindingsFilter(filter, total, findings.length)
    : `${findings.length} findings (full scan)`;

  const intro = [
    "<!-- grephunt-export v1 -->",
    "",
    "# Security scan report",
    "",
    "Structured findings export for triage, remediation handoff, audit notes, or optional LLM analysis.",
    "Each finding has a stable ID (`F-001`, …) for references in tickets and reviews.",
    "",
    metadataSection(scan, scopeLine),
    "",
    summarySection(findings),
  ];

  if (aiReport?.trim()) {
    intro.push("", "---", "", "# AI scan report", "", aiReport.trim());
  }

  intro.push("", "---", "", findingsCatalog(findings));

  const chat = chatMessages?.length ? chatSection(chatMessages) : "";
  if (chat) intro.push("", "---", "", chat);

  intro.push("");
  return intro.join("\n");
}

export function scanExportFilename(scan: ScanSummary, suffix = "export"): string {
  const label = (scan.target_label || "scan")
    .replace(/[^\w.-]+/g, "-")
    .replace(/-+/g, "-")
    .slice(0, 48);
  const id = scan.id.slice(0, 8);
  return `grephunt-${label}-${id}-${suffix}.md`;
}

export function downloadTextFile(filename: string, content: string, mime = "text/markdown;charset=utf-8"): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}
