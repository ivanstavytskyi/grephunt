import { useQueryClient } from "@tanstack/react-query";
import { ListOrdered, LoaderCircle } from "lucide-react";
import { useState } from "react";
import type { Finding } from "@/api/types";
import { readSavedAiKey } from "@/lib/ai-storage";

const BATCH = 24;

/** Ask the configured model for a verdict per finding, in batches; the list then sorts by it. */
export function PrioritizeAi({ scanId, findings }: { scanId: string; findings: Finding[] }) {
  const queryClient = useQueryClient();
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);
  const [note, setNote] = useState("");
  const saved = readSavedAiKey();
  const reviewed = findings.filter((item) => item.ai_verdict).length;

  const run = async (all: boolean) => {
    if (!saved || findings.length === 0) return;
    const queue = all ? findings : findings.filter((item) => !item.ai_verdict);
    if (queue.length === 0) {
      setNote("Every finding already has a verdict.");
      return;
    }
    setNote("");
    let done = 0;
    let ranked = 0;
    setProgress({ done, total: queue.length });
    try {
      for (let start = 0; start < queue.length; start += BATCH) {
        const batch = queue.slice(start, start + BATCH);
        const response = await fetch("/api/ai/prioritize", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ scan_id: scanId, provider: saved.provider, api_key: saved.apiKey, model: saved.model, findings: batch }),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          setNote(typeof body.detail === "string" ? body.detail : "The model did not rank these findings");
          break;
        }
        ranked += Array.isArray(body.verdicts) ? body.verdicts.length : 0;
        done += batch.length;
        setProgress({ done, total: queue.length });
        await queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      }
      if (ranked) setNote(`Reviewed ${ranked}. Confirmed findings move up, likely false positives move down; nothing is deleted.`);
    } catch {
      setNote("Could not reach the console");
    } finally {
      setProgress(null);
    }
  };

  const busy = progress !== null;
  return (
    <span className="inline-flex flex-col gap-1">
      <span className="inline-flex items-center gap-2">
        <button
          type="button"
          disabled={busy || !saved || findings.length === 0}
          onClick={() => void run(false)}
          title={saved ? "Ask the model to confirm each finding or mark it a likely false positive, then sort by that" : "Add a Gemini or DeepSeek key in the AI settings first"}
          className="inline-flex h-9 items-center gap-2 rounded-md border border-signal/60 px-3 text-sm text-ink-text hover:bg-signal/10 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? <LoaderCircle className="size-4 animate-spin" aria-hidden="true" /> : <ListOrdered className="size-4 text-signal" aria-hidden="true" />}
          {busy ? `Reviewing ${progress.done}/${progress.total}` : reviewed ? `Sort with AI (${reviewed} reviewed)` : "Sort with AI"}
        </button>
        {reviewed > 0 && !busy && (
          <button type="button" onClick={() => void run(true)} className="text-xs text-ink-muted underline-offset-2 hover:text-ink-text hover:underline">
            redo all
          </button>
        )}
      </span>
      {note && <span className="max-w-xs text-xs text-ink-muted">{note}</span>}
    </span>
  );
}
