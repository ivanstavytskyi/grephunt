const LABELS: Record<string, { title: string; hint: string }> = {
  vuln: { title: "Vulnerabilities", hint: "CVEs in dependencies and OS packages" },
  secret: { title: "Secrets", hint: "Hardcoded tokens in image layers or files" },
  misconfig: { title: "Misconfigurations", hint: "Dockerfile and IaC issues" },
};

export function MultiParamSettings({
  choices,
  value,
  onChange,
}: {
  choices: string[];
  value: string[];
  onChange: (value: string[]) => void;
}) {
  const toggle = (mode: string) => {
    if (value.includes(mode)) {
      const next = value.filter((item) => item !== mode);
      onChange(next.length > 0 ? next : [mode]);
      return;
    }
    onChange([...value, mode]);
  };

  return (
    <ul className="space-y-2">
      {choices.map((mode) => {
        const on = value.includes(mode);
        const meta = LABELS[mode] ?? { title: mode, hint: "" };
        return (
          <li key={mode}>
            <button
              type="button"
              aria-pressed={on}
              onClick={() => toggle(mode)}
              className={`w-full rounded-md border px-3 py-2 text-left text-sm ${
                on ? "border-signal/60 bg-signal/10" : "border-ink-line hover:border-ink-muted/60"
              }`}
            >
              <span className="font-medium capitalize">{meta.title}</span>
              {meta.hint && <span className="mt-0.5 block text-xs text-ink-muted">{meta.hint}</span>}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
