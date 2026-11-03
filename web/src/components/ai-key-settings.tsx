import { LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { SelectMenu } from "@/components/select-menu";
import { AI_MODELS, AI_STORAGE_KEY, readApiError, readSavedAiKey, type AiProvider, type SavedAiKey } from "@/lib/ai-storage";

export function AiKeySettings({
  open,
  onSaved,
}: {
  open: boolean;
  onSaved: (key: SavedAiKey) => void;
}) {
  const [provider, setProvider] = useState<AiProvider>("gemini");
  const [model, setModel] = useState(AI_MODELS.gemini[0]);
  const [apiKey, setApiKey] = useState("");
  const [checking, setChecking] = useState(false);
  const [setupError, setSetupError] = useState("");

  useEffect(() => {
    const stored = readSavedAiKey();
    if (!stored) return;
    setProvider(stored.provider);
    setModel(stored.model);
    setApiKey(stored.apiKey);
  }, [open]);

  if (!open) return null;

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
        setSetupError(await readApiError(response));
        return;
      }
      const next = { provider, apiKey: apiKey.trim(), model };
      localStorage.setItem(AI_STORAGE_KEY, JSON.stringify(next));
      onSaved(next);
    } catch {
      setSetupError("Could not reach the console");
    } finally {
      setChecking(false);
    }
  };

  return (
    <div className="mt-3 space-y-3 rounded-md border border-ink-line bg-ink-bg p-3">
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
                setModel(AI_MODELS[item][0]);
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
        options={AI_MODELS[provider].map((item) => ({ value: item, label: item }))}
      />
      <label className="block">
        <span className="mb-1.5 block text-xs text-ink-muted">
          {provider === "gemini" ? "Gemini API key" : "DeepSeek API key"}
        </span>
        <input
          type="password"
          value={apiKey}
          autoComplete="off"
          aria-label={provider === "gemini" ? "Gemini API key" : "DeepSeek API key"}
          onChange={(event) => setApiKey(event.target.value)}
          className="h-9 w-full rounded-md border border-ink-line bg-ink-panel px-3 text-sm outline-none focus-visible:ring-2 focus-visible:ring-signal/60"
        />
      </label>
      <button
        type="button"
        disabled={checking}
        onClick={() => void save()}
        className="flex h-9 items-center gap-2 rounded-md bg-signal px-3 text-sm text-ink-bg disabled:opacity-70"
      >
        {checking && <LoaderCircle className="size-3.5 animate-spin" aria-hidden="true" />}
        Save key
      </button>
      {setupError && <p className="text-xs text-ink-muted">{setupError}</p>}
    </div>
  );
}
