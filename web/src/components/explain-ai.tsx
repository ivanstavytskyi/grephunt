import { LoaderCircle, Settings } from "lucide-react";
import { useEffect, useState } from "react";
import type { Finding } from "@/api/types";
import { SelectMenu } from "@/components/select-menu";

const STORAGE_KEY = "grephunt-ai";

type Provider = "gemini" | "deepseek";
type SavedKey = { provider: Provider; apiKey: string; model: string };

const MODELS: Record<Provider, string[]> = {
  gemini: ["gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash"],
  deepseek: ["deepseek-chat", "deepseek-reasoner"],
};

function readSaved(): SavedKey | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as SavedKey;
    if (!parsed.apiKey || !parsed.model || (parsed.provider !== "gemini" && parsed.provider !== "deepseek")) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function readError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return typeof body.detail === "string" ? body.detail : "The provider rejected the key";
  } catch {
    return "The provider rejected the key";
  }
}

export function ExplainAi({ finding }: { finding: Finding }) {
  const [saved, setSaved] = useState<SavedKey | null>(null);
  const [open, setOpen] = useState(false);
  const [provider, setProvider] = useState<Provider>("gemini");
  const [model, setModel] = useState(MODELS.gemini[0]);
  const [apiKey, setApiKey] = useState("");
  const [checking, setChecking] = useState(false);
  const [setupError, setSetupError] = useState("");
  const [explaining, setExplaining] = useState(false);
  const [answer, setAnswer] = useState("");
  const [explainError, setExplainError] = useState("");

  useEffect(() => {
    const stored = readSaved();
    setSaved(stored);
    if (!stored) return;
    setProvider(stored.provider);
    setModel(stored.model);
    setApiKey(stored.apiKey);
  }, []);

  const ready = saved !== null;

  const save = async () => {
    setChecking(true);
    setSetupError("");
    try {
      const response = await fetch("/api/ai/check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, api_key: apiKey, model }),
      });
      if (!response.ok) {
        setSetupError(await readError(response));
        return;
      }
      const next = { provider, apiKey: apiKey.trim(), model };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      setSaved(next);
      setOpen(false);
    } catch {
      setSetupError("Could not reach the console");
    } finally {
      setChecking(false);
    }
  };

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
      {open && (
        <div className="mt-3 space-y-3">
          <fieldset>
            <legend className="mb-1.5 text-xs text-ink-muted">Provider</legend>
            <div className="grid grid-cols-2 gap-2">
              {(["gemini", "deepseek"] as const).map((item) => (
                <button
                  key={item}
                  type="button"
                  aria-pressed={provider === item}
                  onClick={() => {
                    setProvider(item);
                    setModel(MODELS[item][0]);
                  }}
                  className={`h-9 rounded-md border text-sm capitalize ${
                    provider === item ? "border-signal/60 bg-signal/10" : "border-ink-line"
                  }`}
                >
                  {item === "gemini" ? "Gemini" : "DeepSeek"}
                </button>
              ))}
            </div>
          </fieldset>
          <SelectMenu
            label="Model"
            value={model}
            wide
            onChange={setModel}
            options={MODELS[provider].map((item) => ({ value: item, label: item }))}
          />
          <label className="block">
            <span className="mb-1.5 block text-xs text-ink-muted">{provider === "gemini" ? "Gemini API key" : "DeepSeek API key"}</span>
            <input
              type="password"
              value={apiKey}
              autoComplete="off"
              aria-label={provider === "gemini" ? "Gemini API key" : "DeepSeek API key"}
              onChange={(event) => setApiKey(event.target.value)}
              className="h-9 w-full rounded-md border border-ink-line bg-ink-bg px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-signal/60"
            />
          </label>
          <button
            type="button"
            disabled={checking}
            onClick={() => void save()}
            className="flex h-9 items-center gap-2 rounded-md bg-signal px-3 text-sm text-ink-bg disabled:opacity-70"
          >
            {checking && <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" />}
            Save
          </button>
          {setupError && <p className="text-xs text-ink-muted">{setupError}</p>}
        </div>
      )}
      {explainError && <p className="mt-3 text-xs text-ink-muted">{explainError}</p>}
      {answer && <p className="mt-3 whitespace-pre-wrap text-xs leading-5 text-ink-text/90">{answer}</p>}
    </div>
  );
}
