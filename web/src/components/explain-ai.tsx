import { Settings } from "lucide-react";
import { useEffect, useState } from "react";
import type { Finding } from "@/api/types";
import { AiKeySettings } from "@/components/ai-key-settings";
import { readSavedAiKey, type SavedAiKey } from "@/lib/ai-storage";

export function ExplainAi({ finding }: { finding: Finding }) {
  const [saved, setSaved] = useState<SavedAiKey | null>(null);
  const [open, setOpen] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [answer, setAnswer] = useState("");
  const [explainError, setExplainError] = useState("");

  useEffect(() => {
    setSaved(readSavedAiKey());
  }, []);

  const ready = saved !== null;

  const explain = async () => {
    if (!saved) return;
    setExplaining(true);
    setExplainError("");
    setAnswer("");
    try {
      const response = await fetch("/api/ai/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: saved.provider,
          api_key: saved.apiKey,
          model: saved.model,
          finding,
        }),
      });
      const body = await response.json();
      if (!response.ok) {
        setExplainError(typeof body.detail === "string" ? body.detail : "Could not explain this finding");
        return;
      }
      setAnswer(typeof body.text === "string" ? body.text : "");
    } catch {
      setExplainError("Could not reach the console");
    } finally {
      setExplaining(false);
    }
  };

  return (
    <div className="border-t border-ink-line pt-3">
      <div className="flex items-center gap-2">
        <button
          type="button"
          disabled={!ready || explaining}
          onClick={() => void explain()}
          className={`h-9 flex-1 rounded-md border text-sm ${
            ready
              ? "border-signal/60 text-ink-text hover:bg-signal/10"
              : "cursor-not-allowed border-ink-line text-ink-muted"
          }`}
          title={ready ? "Explain this finding" : "Add an API key first"}
        >
          {explaining ? "Explaining…" : "Explain with AI"}
        </button>
        <button
          type="button"
          aria-expanded={open}
          aria-label="AI provider settings"
          title="AI provider settings"
          onClick={() => setOpen((value) => !value)}
          className="flex size-9 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
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
      {explainError && <p className="mt-3 text-xs text-ink-muted">{explainError}</p>}
      {answer && <p className="mt-3 whitespace-pre-wrap text-xs leading-5 text-ink-text/90">{answer}</p>}
    </div>
  );
}
