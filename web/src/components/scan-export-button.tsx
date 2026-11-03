import { Download } from "lucide-react";
import { useMemo } from "react";
import type { Finding, ScanSummary } from "@/api/types";
import { filterFindings, type FindingsFilterState } from "@/lib/findings-filter";
import { buildScanExportMarkdown, downloadTextFile, scanExportFilename } from "@/lib/scan-export";

export function ScanExportButton({
  scan,
  findings,
  filter,
}: {
  scan: ScanSummary | undefined;
  findings: Finding[];
  filter?: FindingsFilterState;
}) {
  const exportRows = useMemo(
    () => (filter ? filterFindings(findings, filter) : findings),
    [filter, findings],
  );
  const disabled = !scan || exportRows.length === 0;

  const onExport = () => {
    if (!scan || exportRows.length === 0) return;
    const markdown = buildScanExportMarkdown({
      scan,
      findings: exportRows,
      filter,
      totalFindings: findings.length,
    });
    downloadTextFile(scanExportFilename(scan, "report"), markdown);
  };

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onExport}
      title="Download markdown report (metadata, summary, and findings in the current filter)"
      aria-label="Export as Markdown"
      className="inline-flex h-9 shrink-0 items-center justify-center gap-2 rounded-md border border-ink-line bg-ink-panel px-3.5 text-sm font-medium text-ink-text shadow-sm shadow-black/20 hover:bg-ink-raised disabled:cursor-not-allowed disabled:opacity-40"
    >
      <Download className="size-4 shrink-0 text-ink-muted" aria-hidden="true" />
      Export
    </button>
  );
}
