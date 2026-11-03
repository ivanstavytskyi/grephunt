import { Minus, Plus, ScrollText } from "lucide-react";
import { useState } from "react";
import { Input } from "@/components/ui/input";

type RulePreview = {
  origin: string;
  source: string;
  total: number;
  shown: number;
  rules: Array<{ id: string; severity: string; message: string }>;
};

function sentence(text: string): string {
  const trimmed = text.trim();
  if (!trimmed) return "Could not read these rules";
  return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
}

export function SemgrepRulesSettings({
  value,
  onChange,
}: {
  value: string;
  onChange: (value: string) => void;
}) {
  const [items, setItems] = useState(() => value.split(",").map((item) => item.trim()).filter(Boolean));
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [preview, setPreview] = useState<RulePreview | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const publish = (next: string[]) => {
    const rows = next.length > 0 ? next : [""];
    setItems(rows);
    onChange(rows.map((item) => item.trim()).filter(Boolean).join(","));
  };

  const load = async (path: string) => {
    setLoading(true);
    setError("");
    setPreview(null);
    try {
      const response = await fetch(`/api/rules?config=${encodeURIComponent(path)}`);
      const body = await response.json();
      if (!response.ok) {
        setError(typeof body.detail === "string" ? sentence(body.detail) : "Could not read these rules");
        return;
      }
      setPreview(body as RulePreview);
    } catch {
      setError("Could not read these rules");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-muted">
        Semgrep rulesets: registry URL, local path, or <span className="font-mono">p/default</span>.
      </p>
      <ul className="space-y-2">
        {items.map((item, index) => (
          <li key={index}>
            <div className="flex items-center gap-2">
              <span className="relative block min-w-0 flex-1">
                <Input
                  value={item}
                  className="pr-10"
                  aria-label={`Ruleset ${index + 1}`}
                  placeholder="https://semgrep.dev/c/p/default"
                  onChange={(event) => {
                    const next = [...items];
                    next[index] = event.target.value;
                    publish(next);
                    if (openIndex === index) setOpenIndex(null);
                  }}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 flex w-10 items-center justify-center text-ink-muted hover:text-ink-text"
                  aria-expanded={openIndex === index}
                  aria-label={`Preview ruleset ${index + 1}`}
                  title="Preview rules in this ruleset"
                  onClick={() => {
                    if (openIndex === index) {
                      setOpenIndex(null);
                      return;
                    }
                    setOpenIndex(index);
                    void load(item);
                  }}
                >
                  <ScrollText className="size-4" aria-hidden="true" />
                </button>
              </span>
              {index === 0 && (
                <button
                  type="button"
                  className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
                  aria-label="Add another ruleset"
                  title="Add another ruleset"
                  onClick={() => publish([...items, ""])}
                >
                  <Plus className="size-4" aria-hidden="true" />
                </button>
              )}
              <button
                type="button"
                className="flex size-9 shrink-0 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:text-ink-text"
                aria-label={`Remove ruleset ${index + 1}`}
                title="Remove this ruleset"
                onClick={() => {
                  publish(items.filter((_, itemIndex) => itemIndex !== index));
                  setOpenIndex(null);
                }}
              >
                <Minus className="size-4" aria-hidden="true" />
              </button>
            </div>
            {openIndex === index && (
              <div className="mt-2 max-h-56 overflow-auto rounded-md border border-ink-line bg-ink-bg p-3 text-sm">
                {loading && <p className="text-ink-muted">Reading rules…</p>}
                {error && <p className="text-ink-muted">{error}</p>}
                {preview && preview.total === 0 && <p className="text-ink-muted">No rules in this ruleset.</p>}
                {preview && preview.total > 0 && (
                  <>
                    <p className="text-xs text-ink-muted">
                      {preview.origin}. {preview.source}. Showing {preview.shown} of {preview.total}.
                    </p>
                    <ul className="mt-3 space-y-3">
                      {preview.rules.map((rule, ruleIndex) => (
                        <li key={`${rule.id}-${ruleIndex}`}>
                          <p className="font-mono text-xs">
                            {rule.severity ? `${rule.severity} · ` : ""}
                            {rule.id}
                          </p>
                          {rule.message && <p className="mt-1 text-xs leading-5 text-ink-muted">{rule.message}</p>}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
