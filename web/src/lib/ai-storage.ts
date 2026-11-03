export const AI_STORAGE_KEY = "grephunt-ai";

export type AiProvider = "gemini" | "deepseek";

export type SavedAiKey = { provider: AiProvider; apiKey: string; model: string };

export const AI_MODELS: Record<AiProvider, string[]> = {
  gemini: ["gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-2.5-flash"],
  deepseek: ["deepseek-chat", "deepseek-reasoner"],
};

export function readSavedAiKey(): SavedAiKey | null {
  try {
    const raw = localStorage.getItem(AI_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as SavedAiKey;
    if (!parsed.apiKey || !parsed.model || (parsed.provider !== "gemini" && parsed.provider !== "deepseek")) return null;
    return parsed;
  } catch {
    return null;
  }
}

export async function readApiError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return typeof body.detail === "string" ? body.detail : "The provider rejected the request";
  } catch {
    return "The provider rejected the request";
  }
}
