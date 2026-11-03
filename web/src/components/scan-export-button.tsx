import { useMemo } from "react";
import type { Finding, ScanSummary } from "@/api/types";
import { ExportMenu } from "@/components/export-menu";
import { filterFindings, type FindingsFilterState } from "@/lib/findings-filter";
import { exportScanReport } from "@/lib/scan-export";

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

  return (
    <ExportMenu
      disabled={!scan || exportRows.length === 0}
      title="Download the report with the findings in the current filter: PDF, Markdown or plain text"
      onExport={(format) => {
        if (!scan || exportRows.length === 0) return;
        exportScanReport(format, { scan, findings: exportRows, filter, totalFindings: findings.length });
      }}
    />
  );
}
