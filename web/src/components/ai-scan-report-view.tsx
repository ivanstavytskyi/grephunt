import { X } from "lucide-react";
import type { Finding } from "@/api/types";
import { AiMarkdownBody } from "@/components/ai-markdown-body";
import { parseReportSections } from "@/lib/ai-report-markdown";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = key(item) || "unknown";
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function severityTone(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-red-500/40 bg-red-500/10 text-red-200";
    case "high":
      return "border-orange-500/40 bg-orange-500/10 text-orange-100";
    case "medium":
      return "border-amber-500/40 bg-amber-500/10 text-amber-100";
    case "low":
      return "border-sky-500/40 bg-sky-500/10 text-sky-100";
    default:
      return "border-ink-line bg-ink-raised text-ink-muted";
  }
}

export function AiScanReportView({
  report,
  findings,
  targetLabel,
  onClose,
}: {
  report: string;
  findings: Finding[];
  targetLabel?: string;
  onClose: () => void;
}) {
  const { title, sections } = parseReportSections(report);
  const bySeverity = countBy(findings, (f) => f.severity);
  const byCategory = countBy(findings, (f) => f.category);

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 p-4 pt-10 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-scan-report-title"
      onClick={onClose}
    >
      <div
        className="flex max-h-[min(88vh,900px)] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-ink-line bg-ink-panel shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex shrink-0 items-start justify-between gap-4 border-b border-ink-line px-5 py-4">
          <div className="min-w-0">
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-signal">AI scan report</p>
            <h2 id="ai-scan-report-title" className="mt-1 text-lg font-semibold leading-snug tracking-tight text-ink-text">
              {title || targetLabel || "Security assessment"}
            </h2>
            <p className="mt-1 text-xs text-ink-muted">{findings.length} findings in this scan</p>
          </div>
          <button
            type="button"
            aria-label="Close report"
            onClick={onClose}
            className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:bg-ink-raised hover:text-ink-text"
          >
            <X className="size-4" aria-hidden="true" />
          </button>
        </header>

        <div className="grid shrink-0 gap-3 border-b border-ink-line bg-ink-bg/40 px-5 py-4 sm:grid-cols-2">
          <div>
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-ink-muted">By severity</p>
            <div className="flex flex-wrap gap-1.5">
              {SEV_ORDER.filter((s) => (bySeverity[s] ?? 0) > 0).map((severity) => (
                <span
                  key={severity}
                  className={`rounded-md border px-2 py-0.5 font-mono text-[11px] capitalize ${severityTone(severity)}`}
                >
                  {severity} {bySeverity[severity]}
                </span>
              ))}
            </div>
          </div>
          <div>
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-ink-muted">By category</p>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(byCategory)
                .sort((a, b) => b[1] - a[1])
                .map(([category, count]) => (
                  <span
                    key={category}
                    className="rounded-md border border-ink-line bg-ink-raised px-2 py-0.5 font-mono text-[11px] capitalize text-ink-muted"
                  >
                    {category} {count}
                  </span>
                ))}
            </div>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {sections.length === 0 ? (
            <article className="rounded-lg border border-ink-line bg-ink-bg/30 p-4">
              <AiMarkdownBody markdown={report} />
            </article>
          ) : (
            <div className="space-y-3">
              {sections.map((section, index) => (
                <article
                  key={`${section.title}-${index}`}
                  className="rounded-lg border border-ink-line bg-ink-bg/30 p-4 shadow-sm shadow-black/20"
                >
                  {section.title && (
                    <h3 className="text-sm font-semibold tracking-tight text-ink-text">{section.title}</h3>
                  )}
                  <div className={section.title ? "mt-2" : ""}>
                    <AiMarkdownBody markdown={section.body} />
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
