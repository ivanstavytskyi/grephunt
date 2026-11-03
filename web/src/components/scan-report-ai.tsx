import { FileText, LoaderCircle, Settings } from "lucide-react";
import { useEffect, useState } from "react";
import type { Finding, ScanSummary } from "@/api/types";
import { aiIcon, secondaryButton } from "@/components/ui/button";
import { AiKeySettings } from "@/components/ai-key-settings";
import { AiScanReportView, type ReportFilterStats } from "@/components/ai-scan-report-view";
import { readApiError, readSavedAiKey, type SavedAiKey } from "@/lib/ai-storage";

export function ScanReportAi({
  scan,
  findings,
}: {
  scan: ScanSummary | undefined;
  findings: Finding[];
}) {
  const [saved, setSaved] = useState<SavedAiKey | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState("");
  const [reportOpen, setReportOpen] = useState(false);
  const [filterStats, setFilterStats] = useState<ReportFilterStats | null>(null);
  const [keptKeys, setKeptKeys] = useState<Set<string> | null>(null);

  useEffect(() => {
    setSaved(readSavedAiKey());
  }, []);

  useEffect(() => {
    if (!reportOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setReportOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [reportOpen]);

  const run = async () => {
    if (!saved) {
      setSettingsOpen(true);
      setError("Add a Gemini or DeepSeek API key first.");
      return;
    }
    if (findings.length === 0) {
      setError("This scan has no findings yet.");
      return;
    }
    setLoading(true);
    setError("");
    setReport("");
    try {
      const response = await fetch("/api/ai/scan-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: saved.provider,
          api_key: saved.apiKey,
          model: saved.model,
          scan: {
            target_label: scan?.target_label,
            target_path: scan?.target_path,
            source_repo_url: scan?.source_repo_url,
            source_ref: scan?.source_ref,
            finding_count: findings.length,
            scanners: scan?.tasks?.map((task) => task.tool),
          },
          findings,
        }),
      });
      const body = await response.json();
      if (!response.ok) {
        setError(typeof body.detail === "string" ? body.detail : await readApiError(response));
        return;
      }
      setReport(typeof body.text === "string" ? body.text : "");
      setFilterStats(body.filter && typeof body.filter === "object" ? (body.filter as ReportFilterStats) : null);
      setKeptKeys(
        Array.isArray(body.kept)
          ? new Set(
              (body.kept as Array<{ fingerprint?: string; correlation_key?: string }>).map(
                (item) => `${item.fingerprint ?? ""}\u0000${item.correlation_key ?? ""}`,
              ),
            )
          : null,
      );
      setReportOpen(true);
    } catch {
      setError("Could not reach the console");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="flex min-w-[12rem] flex-col items-stretch gap-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={loading || findings.length === 0}
            onClick={() => void run()}
            title={
              saved
                ? "AI report on exploitable vulnerabilities only (RCE, injections, LFI/RFI, SSRF, IDOR, access control, auth, XSS/CSRF…). Low-impact and non-exploitable findings are left out."
                : "Add an API key first"
            }
            className={`${secondaryButton} h-9 flex-1 px-3.5`}
          >
            {loading ? (
              <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
            ) : (
              <FileText className={`size-4 ${aiIcon}`} aria-hidden="true" />
            )}
            {loading ? "Analyzing…" : "Provide scan report with AI"}
          </button>
          <button
            type="button"
            aria-expanded={settingsOpen}
            aria-label="AI settings"
            title="AI settings: provider and API key"
            onClick={() => setSettingsOpen((value) => !value)}
            className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted transition-colors hover:bg-ink-raised hover:text-ink-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ink-muted/60"
          >
            <Settings className="size-4" aria-hidden="true" />
          </button>
        </div>
        <AiKeySettings
          open={settingsOpen}
          onSaved={(key) => {
            setSaved(key);
            setSettingsOpen(false);
            setError("");
          }}
        />
        {error && <p className="text-xs text-ink-muted">{error}</p>}
      </div>

      {reportOpen && report && saved && (
        <AiScanReportView
          report={report}
          findings={
            keptKeys
              ? findings.filter((finding) => keptKeys.has(`${finding.fingerprint}\u0000${finding.correlation_key ?? ""}`))
              : findings
          }
          filter={filterStats}
          scan={scan}
          aiKey={saved}
          onClose={() => setReportOpen(false)}
        />
      )}
    </>
  );
}
