import { LoaderCircle, Settings, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";
import type { Finding, ScanSummary } from "@/api/types";
import { AiKeySettings } from "@/components/ai-key-settings";
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

  useEffect(() => {
    setSaved(readSavedAiKey());
  }, []);

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
      setReportOpen(true);
    } catch {
      setError("Could not reach the console");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ml-auto flex min-w-[12rem] flex-col items-stretch gap-2">
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={loading || findings.length === 0}
          onClick={() => void run()}
          title={saved ? "Summarize all findings with AI" : "Add an API key first"}
          className="flex h-9 flex-1 items-center justify-center gap-2 rounded-md border border-signal/60 px-3 text-sm text-ink-text hover:bg-signal/10 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {loading ? (
            <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
          ) : (
            <Sparkles className="size-4 text-signal" aria-hidden="true" />
          )}
          {loading ? "Analyzing…" : "Provide scan report with AI"}
        </button>
        <button
          type="button"
          aria-expanded={settingsOpen}
          aria-label="AI provider settings"
          title="AI provider settings"
          onClick={() => setSettingsOpen((value) => !value)}
          className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
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
      {reportOpen && report && (
        <div className="max-h-96 overflow-auto rounded-md border border-ink-line bg-ink-panel p-3 text-xs leading-5 text-ink-text/90">
          <div className="mb-2 flex items-center justify-between gap-2">
            <p className="font-medium text-ink-text">AI scan report</p>
            <button
              type="button"
              className="text-ink-muted hover:text-ink-text"
              onClick={() => setReportOpen(false)}
            >
              Close
            </button>
          </div>
          <pre className="whitespace-pre-wrap font-sans">{report}</pre>
        </div>
      )}
    </div>
  );
}
