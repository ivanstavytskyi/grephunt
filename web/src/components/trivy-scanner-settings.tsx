const MODES = [
  { id: "vuln", label: "Vulnerabilities", hint: "CVEs in dependencies and OS packages" },
  { id: "secret", label: "Secrets", hint: "Hardcoded tokens in image layers or files" },
  { id: "misconfig", label: "Misconfigurations", hint: "Dockerfile and IaC issues" },
] as const;

export type TrivyScannerMode = (typeof MODES)[number]["id"];

export function TrivyScannerSettings({
  value,
  onChange,
}: {
  value: TrivyScannerMode[];
  onChange: (value: TrivyScannerMode[]) => void;
}) {
  const toggle = (mode: TrivyScannerMode) => {
    if (value.includes(mode)) {
      const next = value.filter((item) => item !== mode);
      onChange(next.length > 0 ? next : [mode]);
      return;
    }
    onChange([...value, mode]);
  };

  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-muted">Trivy scan modes (at least one).</p>
      <ul className="space-y-2">
        {MODES.map((mode) => {
          const on = value.includes(mode.id);
          return (
            <li key={mode.id}>
              <button
                type="button"
                aria-pressed={on}
                onClick={() => toggle(mode.id)}
                className={`w-full rounded-md border px-3 py-2 text-left text-sm ${
                  on ? "border-signal/60 bg-signal/10" : "border-ink-line hover:border-ink-muted/60"
                }`}
              >
                <span className="font-medium capitalize">{mode.label}</span>
                <span className="mt-0.5 block text-xs text-ink-muted">{mode.hint}</span>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
