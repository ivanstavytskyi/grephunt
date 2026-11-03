import type { Finding, ScanSummary, Severity, TaskSummary } from "@/api/types";
import { describeFindingsFilter, type FindingsFilterState } from "@/lib/findings-filter";
import { locationLabel } from "@/lib/utils";

export type AiReportChatMessage = {
  role: "user" | "assistant";
  content: string;
};

/*
 * One report, three formats: Markdown, plain text and a print-ready HTML page for PDF.
 *
 * Layout (inverted pyramid): summary and totals, an optional AI analysis, every finding
 * grouped by severity, scanner status, scan details. Severity is a word, not a
 * colored symbol; no emoji, no decorative bars. Each finding has a stable ID (F-001) so
 * tickets and reviews can refer to it.
 */

export type ExportFormat = "pdf" | "md" | "txt";

const SNIPPET_LINES = 8;
const MESSAGE_MAX = 320;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};
const CATEGORY_LABEL: Record<string, string> = {
  code: "Code",
  secret: "Secret",
  dependency: "Dependency",
  misconfig: "Misconfiguration",
};
const STATUS_LABEL: Record<string, string> = {
  success: "Finished",
  failed: "Failed",
  timeout: "Timed out",
  skipped: "Skipped",
  running: "Running",
  queued: "Queued",
};
const VERDICT_LABEL: Record<string, string> = {
  confirmed: "confirmed in the code",
  likely: "likely real",
  false_positive: "likely a false positive",
};

// ---------- Report model ----------

type FindingEntry = {
  id: string;
  severity: Severity;
  title: string;
  location: string;
  category: string;
  tools: string[];
  message: string;
  rule: string;
  references: string[];
  fixedVersion: string;
  exploitability: string;
  aiReview: string;
  helpUri: string;
  snippet: string;
  snippetLang: string;
  sameIssueLines: string;
  ids: string;
  verdict: string;
};

type ScannerEntry = {
  name: string;
  status: string;
  findings: string;
  time: string;
  version: string;
  note: string;
};

type ReportModel = {
  title: string;
  totalFindings: number;
  severityCounts: { severity: Severity; count: number }[];
  categoryCounts: { category: string; count: number }[];
  summaryLine: string;
  incomplete: string;
  filterNote: string;
  groups: { severity: Severity; findings: FindingEntry[] }[];
  scanners: ScannerEntry[];
  details: [string, string][];
  aiReport: string;
  chat: AiReportChatMessage[];
  generatedAt: string;
};

function severityOf(finding: Finding): Severity {
  return SEVERITIES.includes(finding.severity) ? finding.severity : "info";
}

function oneLine(value: string | null | undefined): string {
  return (value ?? "").replace(/\s+/g, " ").trim();
}

function truncate(value: string | null | undefined, max: number): string {
  if (!value) return "";
  const normalized = value.replace(/\r\n/g, "\n").trim();
  if (normalized.length <= max) return normalized;
  return `${normalized.slice(0, max - 1).trimEnd()}…`;
}

function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

function formatSeconds(value: number | null | undefined): string {
  if (value == null || !Number.isFinite(value)) return "—";
  const total = Math.round(value);
  if (total < 60) return `${total} s`;
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  if (minutes < 60) return seconds ? `${minutes} min ${seconds} s` : `${minutes} min`;
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

function scanDuration(scan: ScanSummary): number | null {
  if (scan.created_at && scan.finished_at) {
    const start = Date.parse(scan.created_at);
    const end = Date.parse(scan.finished_at);
    if (!Number.isNaN(start) && !Number.isNaN(end)) return Math.max(0, (end - start) / 1000);
  }
  return scan.duration_sec ?? null;
}

function toolsOf(finding: Finding): string[] {
  const names = [finding.tool, ...(finding.tools ?? []), ...(finding.confirmations ?? []).map((item) => item.tool)];
  // Correlated findings can carry "grype+osv-scanner" as one name.
  return [...new Set(names.flatMap((name) => (name ?? "").split("+")).map((name) => name.trim()).filter(Boolean))];
}

function locationOf(finding: Finding): string {
  return finding.location ? locationLabel(finding.location) : "";
}

function findingTitle(finding: Finding): string {
  if (finding.package) {
    const version = finding.installed_version ? ` ${finding.installed_version}` : "";
    return `${finding.package}${version}: ${finding.cve?.[0] ?? finding.title}`;
  }
  return oneLine(finding.title || finding.rule_id) || "Untitled finding";
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) => {
    const bySeverity = SEVERITIES.indexOf(severityOf(left)) - SEVERITIES.indexOf(severityOf(right));
    if (bySeverity) return bySeverity;
    const byScore = (right.exploitability?.score ?? 0) - (left.exploitability?.score ?? 0);
    if (byScore) return byScore;
    const byTools = toolsOf(right).length - toolsOf(left).length;
    if (byTools) return byTools;
    return locationOf(left).localeCompare(locationOf(right));
  });
}

function shortSnippet(value: string | null | undefined): string {
  if (!value) return "";
  const lines = value.replace(/\r\n/g, "\n").replace(/^\n+|\s+$/g, "").split("\n");
  const kept = lines.slice(0, SNIPPET_LINES).map((line) => (line.length > 160 ? `${line.slice(0, 159)}…` : line));
  if (lines.length > SNIPPET_LINES) kept.push(`… ${lines.length - SNIPPET_LINES} more lines`);
  return kept.join("\n");
}

function entryOf(finding: Finding, id: string): FindingEntry {
  const references: string[] = [];
  if (finding.cve?.length) references.push(`CVE: ${finding.cve.join(", ")}`);
  if (finding.cwe?.length) references.push(`CWE: ${finding.cwe.join(", ")}`);
  if (finding.owasp?.length) references.push(`OWASP: ${finding.owasp.join(", ")}`);
  const exploitability = finding.exploitability
    ? `${finding.exploitability.label} (${finding.exploitability.score}/100)${
        finding.exploitability.factors?.length ? `: ${finding.exploitability.factors.join("; ")}` : ""
      }`
    : "";
  const verdict = finding.ai_verdict ? VERDICT_LABEL[finding.ai_verdict] ?? "" : "";
  let message = truncate(finding.message || finding.description, MESSAGE_MAX);
  if (finding.category === "dependency") {
    // Package findings list every advisory after " - "; the IDs are already in the meta line.
    message = message.split(/\s-\s(?=critical|high|medium|low|info)\b/i)[0].trim();
  }
  return {
    id,
    severity: severityOf(finding),
    title: findingTitle(finding),
    location: locationOf(finding),
    category: CATEGORY_LABEL[finding.category] ?? finding.category ?? "Code",
    tools: toolsOf(finding),
    message: message && oneLine(message) !== oneLine(finding.title) ? message : "",
    rule: `${finding.rule_id || "—"}${finding.tool_version ? ` (${finding.tool} ${finding.tool_version})` : ""}`,
    references,
    fixedVersion: finding.fixed_version ?? "",
    exploitability,
    aiReview: verdict ? `${verdict}${finding.ai_reason ? `. ${truncate(oneLine(finding.ai_reason), 300)}` : ""}` : "",
    helpUri: finding.help_uri ?? "",
    snippet: shortSnippet(finding.snippet),
    snippetLang: finding.location?.path?.split(".").pop()?.toLowerCase() ?? "",
    sameIssueLines: (finding.lines?.length ?? 0) > 1 ? (finding.lines ?? []).join(", ") : "",
    ids: [...(finding.cve ?? []), ...(finding.cwe ?? [])].slice(0, 4).join(", "),
    verdict,
  };
}

function scannerEntries(tasks: TaskSummary[]): ScannerEntry[] {
  const order: Record<string, number> = { failed: 0, timeout: 0, running: 1, queued: 1, success: 2, skipped: 3 };
  return [...tasks]
    .sort((left, right) => (order[left.status] ?? 4) - (order[right.status] ?? 4) || left.tool.localeCompare(right.tool))
    .map((task) => {
      const found = task.details?.accepted ?? task.details?.raw_findings;
      const problem = task.status === "failed" || task.status === "timeout" || task.status === "skipped";
      return {
        name: task.tool,
        status: STATUS_LABEL[task.status] ?? task.status,
        findings: found != null ? String(found) : "—",
        time: formatSeconds(task.duration_sec),
        version: task.tool_version ?? "—",
        note: problem ? truncate(oneLine(task.error?.split("\n").find((line) => line.trim()) ?? ""), 160) : "",
      };
    });
}

function buildModel(options: ScanExportOptions): ReportModel {
  const { scan, findings, filter, totalFindings, aiReport, chatMessages } = options;
  const total = totalFindings ?? findings.length;
  const scope = filter ? describeFindingsFilter(filter, total, findings.length) : `${findings.length} findings (full scan)`;
  const sorted = sortFindings(findings);
  const entries = sorted.map((finding, index) => entryOf(finding, `F-${String(index + 1).padStart(3, "0")}`));

  const severityCounts = SEVERITIES.map((severity) => ({
    severity,
    count: entries.filter((entry) => entry.severity === severity).length,
  })).filter((item) => item.count > 0);
  const byCategory = new Map<string, number>();
  for (const entry of entries) byCategory.set(entry.category, (byCategory.get(entry.category) ?? 0) + 1);

  const tasks = scan.tasks ?? [];
  const failed = tasks.filter((task) => task.status === "failed" || task.status === "timeout");
  const counts = severityCounts.map((item) => `${item.count} ${item.severity}`).join(", ");
  const target = scan.target_label || "scan";

  return {
    title: `Security scan report: ${target}`,
    totalFindings: entries.length,
    severityCounts,
    categoryCounts: [...byCategory.entries()]
      .sort((left, right) => right[1] - left[1])
      .map(([category, count]) => ({ category, count })),
    summaryLine:
      `${entries.length} findings${counts ? ` (${counts})` : ""}. ` +
      `Scanned ${formatDate(scan.created_at)} in ${formatSeconds(scanDuration(scan))} with ${tasks.length} scanners.`,
    incomplete: failed.length
      ? `${failed.length} of ${tasks.length} scanners did not finish (${failed.map((task) => task.tool).join(", ")}). Results may be incomplete; see Scanners.`
      : "",
    filterNote: filter && !scope.includes("full scan") ? `Filtered export: ${scope}.` : "",
    groups: SEVERITIES.map((severity) => ({
      severity,
      findings: entries.filter((entry) => entry.severity === severity),
    })).filter((group) => group.findings.length > 0),
    scanners: scannerEntries(tasks),
    details: [
      ["Scan ID", scan.id],
      ["Target", target],
      [
        "Source",
        scan.source_repo_url ? `${scan.source_repo_url}${scan.source_ref ? ` (${scan.source_ref})` : ""}` : "Uploaded files",
      ],
      ["Path", scan.target_path || "—"],
      ["Status", `${scan.status}${scan.partial ? ", some scanners failed" : ""}`],
      ["Started", formatDate(scan.created_at)],
      ["Finished", formatDate(scan.finished_at)],
      ["Duration", formatSeconds(scanDuration(scan))],
      ["Raw results", `${scan.raw_total ?? 0}, of which ${scan.excluded ?? 0} excluded (tests, build output, noise)`],
      ["This export", scope],
    ],
    aiReport: (aiReport ?? "").trim(),
    chat: chatMessages ?? [],
    generatedAt: formatDate(new Date().toISOString()),
  };
}

function demoteHeadings(markdown: string, levels: number): string {
  return markdown
    .replace(/^#\s+.*\n+/, "")
    .replace(/^(#{1,6})\s/gm, (_match, hashes: string) => `${"#".repeat(Math.min(6, hashes.length + levels))} `);
}

// ---------- Shared layout ----------
//
// 1. Title, one summary line, a note when scanners failed.
// 2. Overview: totals by severity, then one table with every finding (ID, severity, finding, location).
// 3. AI analysis, when the export comes from the AI report.
// 4. Finding details: one short block per finding (location, weakness IDs, scanners, message, code).
// 5. Appendix: scanner status and scan details.

function metaParts(entry: FindingEntry): string[] {
  const tools =
    entry.tools.length > 3 ? `${entry.tools.slice(0, 3).join(", ")} +${entry.tools.length - 3}` : entry.tools.join(", ");
  return [
    entry.category,
    entry.ids,
    entry.fixedVersion ? `fixed in ${entry.fixedVersion}` : "",
    entry.verdict ? `AI review: ${entry.verdict}` : "",
    tools ? `detected by ${tools}` : "",
  ].filter(Boolean);
}

// ---------- Markdown ----------

function mdCell(value: string): string {
  return value ? value.replace(/\r?\n/g, " ").replace(/\|/g, "\\|") : "—";
}

function mdCode(value: string): string {
  const clean = value.replace(/\r?\n/g, " ");
  return clean.includes("`") ? `\`\` ${clean} \`\`` : `\`${clean}\``;
}

function mdFence(text: string, lang: string): string {
  const fence = text.includes("```") ? "````" : "```";
  return `${fence}${lang}\n${text}\n${fence}`;
}

function allEntries(model: ReportModel): FindingEntry[] {
  return model.groups.flatMap((group) => group.findings);
}

function toMarkdown(model: ReportModel): string {
  const entries = allEntries(model);
  const out: string[] = [`# ${model.title}`, "", model.summaryLine];
  if (model.incomplete) out.push("", `> **Note:** ${model.incomplete}`);
  if (model.filterNote) out.push("", `> ${model.filterNote}`);

  out.push("", "## Overview", "");
  out.push(
    `| ${model.severityCounts.map((item) => SEVERITY_LABEL[item.severity]).join(" | ")} | Total |`,
    `|${" ---: |".repeat(model.severityCounts.length + 1)}`,
    `| ${model.severityCounts.map((item) => item.count).join(" | ")} | **${model.totalFindings}** |`,
  );
  if (entries.length) {
    out.push("", "| ID | Severity | Finding | Location |", "| --- | --- | --- | --- |");
    for (const entry of entries) {
      out.push(
        `| ${entry.id} | ${SEVERITY_LABEL[entry.severity]} | ${mdCell(truncate(entry.title, 80))} | ${
          entry.location ? mdCode(truncate(entry.location, 64)) : "—"
        } |`,
      );
    }
  }

  if (model.aiReport) out.push("", "## AI analysis", "", demoteHeadings(model.aiReport, 1));

  if (entries.length) {
    out.push("", "## Finding details");
    for (const entry of entries) {
      out.push("", `### ${entry.id} · ${SEVERITY_LABEL[entry.severity]} · ${entry.title}`, "");
      out.push([entry.location ? mdCode(entry.location) : "", ...metaParts(entry)].filter(Boolean).join(" · "));
      if (entry.message) out.push("", entry.message);
      if (entry.snippet) out.push("", mdFence(entry.snippet, entry.snippetLang));
    }
  }

  out.push("", "## Appendix", "", "### Scanners", "", "| Scanner | Status | Findings | Time | Note |", "| --- | --- | ---: | ---: | --- |");
  for (const scanner of model.scanners) {
    out.push(`| ${scanner.name} | ${scanner.status} | ${scanner.findings} | ${scanner.time} | ${mdCell(scanner.note)} |`);
  }
  out.push("", "### Scan details", "", "| | |", "| --- | --- |");
  for (const [key, value] of model.details) out.push(`| ${key} | ${mdCell(value)} |`);

  if (model.chat.length) {
    out.push("", "### Follow-up questions");
    for (const message of model.chat) {
      out.push("", message.role === "user" ? "**Question**" : "**Answer**", "", message.content.trim());
    }
  }
  out.push("", "---", "", `Generated by GrepHunt on ${model.generatedAt}.`, "");
  return out.join("\n");
}

// ---------- Plain text ----------

function wrap(text: string, width = 96, indent = ""): string {
  const lines: string[] = [];
  for (const paragraph of text.replace(/\r\n/g, "\n").split("\n")) {
    let line = "";
    for (const word of paragraph.split(/\s+/).filter(Boolean)) {
      if (line && `${line} ${word}`.length > width - indent.length) {
        lines.push(indent + line);
        line = word;
      } else {
        line = line ? `${line} ${word}` : word;
      }
    }
    lines.push(indent + line);
  }
  return lines.join("\n");
}

function textTable(headers: string[], rows: string[][], rightAligned: number[] = []): string {
  const widths = headers.map((header, column) =>
    Math.min(60, Math.max(header.length, ...rows.map((row) => (row[column] ?? "").length))),
  );
  const fit = (value: string, column: number) => {
    const clipped = value.length > widths[column] ? `${value.slice(0, widths[column] - 1)}…` : value;
    return rightAligned.includes(column) ? clipped.padStart(widths[column]) : clipped.padEnd(widths[column]);
  };
  const line = (row: string[]) => row.map((value, column) => fit(value ?? "", column)).join("  ").trimEnd();
  return [line(headers), widths.map((width) => "-".repeat(width)).join("  "), ...rows.map(line)].join("\n");
}

function underline(text: string, char = "="): string {
  return `${text}\n${char.repeat(text.length)}`;
}

function markdownToText(markdown: string): string {
  return markdown
    .replace(/^#{1,6}\s+(.*)$/gm, (_match, title: string) => title.toUpperCase())
    .replace(/\*\*(.+?)\*\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)");
}

function toText(model: ReportModel): string {
  const entries = allEntries(model);
  const out: string[] = [underline(model.title), "", wrap(model.summaryLine)];
  if (model.incomplete) out.push("", wrap(`NOTE: ${model.incomplete}`));
  if (model.filterNote) out.push("", wrap(model.filterNote));

  out.push("", "", underline("OVERVIEW", "-"), "");
  out.push(
    textTable(
      [...model.severityCounts.map((item) => SEVERITY_LABEL[item.severity]), "Total"],
      [[...model.severityCounts.map((item) => String(item.count)), String(model.totalFindings)]],
      model.severityCounts.map((_item, index) => index).concat(model.severityCounts.length),
    ),
  );
  if (entries.length) {
    out.push(
      "",
      textTable(
        ["ID", "Severity", "Finding", "Location"],
        entries.map((entry) => [entry.id, SEVERITY_LABEL[entry.severity], entry.title, entry.location || "—"]),
      ),
    );
  }

  if (model.aiReport) out.push("", "", underline("AI ANALYSIS", "-"), "", markdownToText(demoteHeadings(model.aiReport, 0)));

  if (entries.length) {
    out.push("", "", underline("FINDING DETAILS", "-"));
    for (const entry of entries) {
      out.push("", `${entry.id}  ${SEVERITY_LABEL[entry.severity].toUpperCase()}  ${entry.title}`);
      out.push(wrap([entry.location, ...metaParts(entry)].filter(Boolean).join(" · "), 96, "  "));
      if (entry.message) out.push(wrap(entry.message, 96, "  "));
      if (entry.snippet) out.push(entry.snippet.split("\n").map((line) => `    | ${line}`).join("\n"));
    }
  }

  out.push("", "", underline("APPENDIX: SCANNERS", "-"), "");
  out.push(
    textTable(
      ["Scanner", "Status", "Findings", "Time", "Note"],
      model.scanners.map((scanner) => [scanner.name, scanner.status, scanner.findings, scanner.time, scanner.note]),
      [2, 3],
    ),
  );
  out.push("", "", underline("APPENDIX: SCAN DETAILS", "-"), "");
  for (const [key, value] of model.details) out.push(`${`${key}:`.padEnd(14)}${value}`);

  if (model.chat.length) {
    out.push("", "", underline("FOLLOW-UP QUESTIONS", "-"));
    for (const message of model.chat) {
      out.push("", message.role === "user" ? "Question:" : "Answer:", wrap(markdownToText(message.content.trim()), 96, "  "));
    }
  }
  out.push("", "", `Generated by GrepHunt on ${model.generatedAt}.`, "");
  return out.join("\n");
}

// ---------- HTML for PDF ----------

function esc(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** A small, safe markdown subset for the AI analysis and chat: headings, lists, bold, code, paragraphs. */
function miniMarkdown(markdown: string): string {
  const inline = (text: string) =>
    esc(text)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  const html: string[] = [];
  let list: "ul" | "ol" | null = null;
  const closeList = () => {
    if (list) html.push(`</${list}>`);
    list = null;
  };
  for (const raw of markdown.replace(/\r\n/g, "\n").split("\n")) {
    const line = raw.trimEnd();
    const headingMatch = line.match(/^(#{1,6})\s+(.*)$/);
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    const numbered = line.match(/^\s*\d+[.)]\s+(.*)$/);
    if (headingMatch) {
      closeList();
      const level = Math.min(6, headingMatch[1].length + 2);
      html.push(`<h${level}>${inline(headingMatch[2])}</h${level}>`);
    } else if (bullet || numbered) {
      const kind = bullet ? "ul" : "ol";
      if (list !== kind) {
        closeList();
        html.push(`<${kind}>`);
        list = kind;
      }
      html.push(`<li>${inline((bullet ?? numbered)![1])}</li>`);
    } else if (!line.trim()) {
      closeList();
    } else {
      closeList();
      html.push(`<p>${inline(line)}</p>`);
    }
  }
  closeList();
  return html.join("\n");
}

const PRINT_CSS = `
@page { size: A4; margin: 16mm 14mm; }
* { box-sizing: border-box; }
body { font: 9.5pt/1.45 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; color: #1a1d23; margin: 0; }
h1 { font-size: 17pt; margin: 0 0 3pt; font-weight: 600; }
h2 { font-size: 12.5pt; margin: 18pt 0 6pt; padding-bottom: 3pt; border-bottom: 1px solid #c9ced6; font-weight: 600; break-after: avoid; }
h3 { font-size: 10pt; margin: 12pt 0 4pt; font-weight: 600; }
h4, h5, h6 { font-size: 9.5pt; margin: 8pt 0 3pt; }
p { margin: 0 0 5pt; }
ul, ol { margin: 0 0 5pt; padding-left: 16pt; }
.muted { color: #4f5764; }
.note { border-left: 3px solid #b8873a; background: #faf6ee; padding: 5pt 8pt; margin: 8pt 0; }
table { border-collapse: collapse; width: 100%; margin: 4pt 0 8pt; font-size: 8.5pt; }
th, td { text-align: left; padding: 2.5pt 6pt; border-bottom: 1px solid #e6e8ec; vertical-align: top; }
th { font-weight: 600; border-bottom: 1px solid #9aa3af; }
.num { text-align: right; white-space: nowrap; }
td:first-child, th:first-child { white-space: nowrap; }
table.totals { width: auto; margin: 2pt 0 12pt; border: 1px solid #e6e8ec; }
table.totals th, table.totals td { width: 62pt; text-align: center; padding: 4pt 8pt; border: 0; }
table.totals th { font-size: 8pt; font-weight: 600; border-bottom: 1px solid #e6e8ec; }
table.totals td { font-size: 14pt; font-weight: 600; }
table.totals th + th, table.totals td + td { border-left: 1px solid #e6e8ec; }
code, pre { font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace; font-size: 8pt; }
code { word-break: break-all; }
pre { background: #f6f7f9; border: 1px solid #e6e8ec; padding: 4pt 6pt; white-space: pre-wrap; word-break: break-all; margin: 4pt 0 0; }
.sev { font-weight: 600; }
.sev-critical { color: #9b1219; } .sev-high { color: #9a4500; } .sev-medium { color: #6f5300; }
.sev-low { color: #2f4f7f; } .sev-info { color: #4f5764; }
.finding { border-top: 1px solid #e6e8ec; padding: 7pt 0 6pt; break-inside: avoid; }
.finding h3 { margin: 0 0 2pt; }
.finding .meta { color: #4f5764; font-size: 8.5pt; margin-bottom: 3pt; }
.appendix { break-before: page; }
footer { margin-top: 16pt; font-size: 8pt; color: #4f5764; }
`;

function sevSpan(severity: Severity): string {
  return `<span class="sev sev-${severity}">${SEVERITY_LABEL[severity]}</span>`;
}

function toHtml(model: ReportModel, documentTitle: string): string {
  const entries = allEntries(model);
  const out: string[] = [
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${esc(documentTitle)}</title><style>${PRINT_CSS}</style></head><body>`,
    `<h1>${esc(model.title)}</h1>`,
    `<p class="muted">${esc(model.summaryLine)}</p>`,
  ];
  if (model.incomplete) out.push(`<p class="note">${esc(model.incomplete)}</p>`);
  if (model.filterNote) out.push(`<p class="muted">${esc(model.filterNote)}</p>`);

  out.push("<h2>Overview</h2>", '<table class="totals"><thead><tr>');
  for (const item of model.severityCounts) out.push(`<th>${sevSpan(item.severity)}</th>`);
  out.push("<th>Total</th></tr></thead><tbody><tr>");
  for (const item of model.severityCounts) out.push(`<td>${item.count}</td>`);
  out.push(`<td>${model.totalFindings}</td></tr></tbody></table>`);

  if (entries.length) {
    out.push("<table><thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th></tr></thead><tbody>");
    for (const entry of entries) {
      out.push(
        `<tr><td>${entry.id}</td><td>${sevSpan(entry.severity)}</td><td>${esc(truncate(entry.title, 110))}</td><td>${
          entry.location ? `<code>${esc(entry.location)}</code>` : "—"
        }</td></tr>`,
      );
    }
    out.push("</tbody></table>");
  }

  if (model.aiReport) out.push("<h2>AI analysis</h2>", miniMarkdown(demoteHeadings(model.aiReport, 0)));

  if (entries.length) {
    out.push('<h2 style="break-before: page">Finding details</h2>');
    for (const entry of entries) {
      out.push(
        '<section class="finding">',
        `<h3>${entry.id} · ${sevSpan(entry.severity)} · ${esc(entry.title)}</h3>`,
        `<div class="meta">${[entry.location ? `<code>${esc(entry.location)}</code>` : "", ...metaParts(entry).map(esc)]
          .filter(Boolean)
          .join(" · ")}</div>`,
      );
      if (entry.message) out.push(`<p>${esc(entry.message)}</p>`);
      if (entry.snippet) out.push(`<pre>${esc(entry.snippet)}</pre>`);
      out.push("</section>");
    }
  }

  out.push(
    '<div class="appendix">',
    "<h2>Appendix: scanners</h2>",
    '<table><thead><tr><th>Scanner</th><th>Status</th><th class="num">Findings</th><th class="num">Time</th><th>Note</th></tr></thead><tbody>',
  );
  for (const scanner of model.scanners) {
    out.push(
      `<tr><td>${esc(scanner.name)}</td><td>${esc(scanner.status)}</td><td class="num">${esc(scanner.findings)}</td><td class="num">${esc(
        scanner.time,
      )}</td><td>${esc(scanner.note)}</td></tr>`,
    );
  }
  out.push("</tbody></table>", "<h2>Appendix: scan details</h2>", "<table><tbody>");
  for (const [key, value] of model.details) out.push(`<tr><th>${esc(key)}</th><td>${esc(value)}</td></tr>`);
  out.push("</tbody></table>");

  if (model.chat.length) {
    out.push("<h2>Follow-up questions</h2>");
    for (const message of model.chat) {
      out.push(`<h4>${message.role === "user" ? "Question" : "Answer"}</h4>`, miniMarkdown(message.content.trim()));
    }
  }
  out.push("</div>", `<footer>Generated by GrepHunt on ${esc(model.generatedAt)}.</footer>`, "</body></html>");
  return out.join("\n");
}

// ---------- Public API ----------

export type ScanExportOptions = {
  scan: ScanSummary;
  findings: Finding[];
  filter?: FindingsFilterState;
  totalFindings?: number;
  aiReport?: string;
  chatMessages?: AiReportChatMessage[];
};

export function buildScanExportMarkdown(options: ScanExportOptions): string {
  return toMarkdown(buildModel(options));
}

export function buildScanExportText(options: ScanExportOptions): string {
  return toText(buildModel(options));
}

export function buildScanExportHtml(options: ScanExportOptions, documentTitle: string): string {
  return toHtml(buildModel(options), documentTitle);
}

export function scanExportFilename(scan: ScanSummary, suffix = "export", extension = "md"): string {
  const label = (scan.target_label || "scan")
    .replace(/[^\w.-]+/g, "-")
    .replace(/-+/g, "-")
    .slice(0, 48);
  const id = scan.id.slice(0, 8);
  return `grephunt-${label}-${id}-${suffix}.${extension}`;
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

/**
 * PDF through the browser's print dialog ("Save as PDF"): the report is laid out as an A4
 * document in a hidden frame. The document title becomes the suggested file name.
 */
function printHtml(html: string): void {
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  frame.tabIndex = -1;
  Object.assign(frame.style, { position: "fixed", right: "0", bottom: "0", width: "0", height: "0", border: "0" });
  document.body.appendChild(frame);
  let removed = false;
  const cleanup = () => {
    if (removed) return;
    removed = true;
    window.setTimeout(() => frame.remove(), 500);
  };
  frame.onload = () => {
    const view = frame.contentWindow;
    if (!view) {
      cleanup();
      return;
    }
    view.addEventListener("afterprint", cleanup, { once: true });
    view.focus();
    view.print();
    window.setTimeout(cleanup, 120_000);
  };
  frame.srcdoc = html;
}

export function exportScanReport(format: ExportFormat, options: ScanExportOptions, suffix = "report"): void {
  const { scan } = options;
  if (format === "md") {
    downloadTextFile(scanExportFilename(scan, suffix, "md"), buildScanExportMarkdown(options));
  } else if (format === "txt") {
    downloadTextFile(scanExportFilename(scan, suffix, "txt"), buildScanExportText(options), "text/plain;charset=utf-8");
  } else {
    printHtml(buildScanExportHtml(options, scanExportFilename(scan, suffix, "pdf").replace(/\.pdf$/, "")));
  }
}

export const EXPORT_FORMATS: { format: ExportFormat; label: string; hint: string }[] = [
  { format: "pdf", label: "PDF document", hint: "A4 layout for sharing and printing" },
  { format: "md", label: "Markdown (.md)", hint: "For a README, wiki, GitHub or GitLab" },
  { format: "txt", label: "Plain text (.txt)", hint: "For email, tickets and terminals" },
];
