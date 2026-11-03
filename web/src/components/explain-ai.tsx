import { aiButton, aiIcon } from "@/components/ui/button";
import { FileSearch, FlaskConical, Settings } from "lucide-react";
import { useEffect, useState } from "react";
import type { Finding } from "@/api/types";
import { AiKeySettings } from "@/components/ai-key-settings";
import { AiMarkdownBody } from "@/components/ai-markdown-body";
import { readSavedAiKey, type SavedAiKey } from "@/lib/ai-storage";

type Mode = "explain" | "poc";

export function ExplainAi({ finding }: { finding: Finding }) {
  const [saved, setSaved] = useState<SavedAiKey | null>(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<Mode | null>(null);
  const [answer, setAnswer] = useState("");
  const [answerMode, setAnswerMode] = useState<Mode>("explain");
  const [error, setError] = useState("");

  useEffect(() => {
    setSaved(readSavedAiKey());
  }, []);

  const ready = saved !== null;
  // A PoC is a validation walkthrough for a reachable code or misconfiguration finding in your own app.
  const canPoc = finding.category === "code" || finding.category === "misconfig";

  const run = async (mode: Mode) => {
    if (!saved) return;
    setBusy(mode);
    setError("");
    setAnswer("");
    setAnswerMode(mode);
    try {
      const response = await fetch(mode === "poc" ? "/api/ai/poc" : "/api/ai/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: saved.provider, api_key: saved.apiKey, model: saved.model, finding }),
      });
      const body = await response.json();
      if (!response.ok) {
        setError(typeof body.detail === "string" ? body.detail : "The model could not answer");
        return;
      }
      setAnswer(typeof body.text === "string" ? body.text : "");
    } catch {
      setError("Could not reach the console");
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="border-t border-ink-line pt-3">
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!ready || busy !== null}
          onClick={() => void run("explain")}
          className={`${aiButton} h-9 flex-1`}
          title={ready ? "Explain this finding" : "Add an API key first"}
        >
          <FileSearch className={`size-4 ${aiIcon}`} aria-hidden="true" />
          {busy === "explain" ? "Explaining…" : "Explain with AI"}
        </button>
        {canPoc && (
          <button
            type="button"
            disabled={!ready || busy !== null}
            onClick={() => void run("poc")}
            className={`inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-md border text-sm ${
              ready ? "border-orange-400/50 text-ink-text hover:bg-orange-500/10" : "cursor-not-allowed border-ink-line text-ink-muted"
            }`}
            title={ready ? "Validate this finding against your own app and show how to confirm and fix it" : "Add an API key first"}
          >
            <FlaskConical className="size-4" aria-hidden="true" />
            {busy === "poc" ? "Working…" : "Proof of concept"}
          </button>
        )}
        <button
          type="button"
          aria-expanded={open}
          aria-label="AI provider settings"
          title="AI provider settings"
          onClick={() => setOpen((value) => !value)}
          className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
        >
          <Settings className="size-4" aria-hidden="true" />
        </button>
      </div>
      <AiKeySettings
        open={open}
        onSaved={(key) => {
          setSaved(key);
          setOpen(false);
        }}
      />
      {error && <p className="mt-3 text-xs text-ink-muted">{error}</p>}
      {answer && (
        <div className="mt-3">
          {answerMode === "poc" && (
            <p className="mb-2 text-[11px] text-ink-muted">
              Validation for your own scanned app. Run it only against an instance you control.
            </p>
          )}
          <AiMarkdownBody markdown={answer} />
        </div>
      )}
    </div>
  );
}
