import type { ToolParameterSpec } from "@/api/types";
import { SemgrepRulesSettings } from "@/components/semgrep-rules-settings";
import { MultiParamSettings } from "@/components/multi-param-settings";

export function ScannerParamForm({
  specs,
  values,
  onChange,
}: {
  specs: ToolParameterSpec[];
  values: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
}) {
  return (
    <div className="space-y-4">
      {specs.map((spec) => {
        if (spec.widget === "semgrep_rules" && spec.type === "string_list") {
          const list = Array.isArray(values[spec.name]) ? (values[spec.name] as string[]) : [];
          return (
            <div key={spec.name}>
              {spec.label && <p className="mb-1 text-xs font-medium text-ink-text">{spec.label}</p>}
              <SemgrepRulesSettings
                value={list.join(",")}
                onChange={(raw) => {
                  const configs = raw
                    .split(",")
                    .map((item) => item.trim())
                    .filter(Boolean);
                  onChange({ ...values, [spec.name]: configs });
                }}
              />
            </div>
          );
        }
        if (spec.type === "multi") {
          const current = Array.isArray(values[spec.name]) ? (values[spec.name] as string[]) : [];
          return (
            <div key={spec.name}>
              {spec.label && <p className="mb-1 text-xs font-medium text-ink-text">{spec.label}</p>}
              {spec.description && <p className="mb-2 text-xs text-ink-muted">{spec.description}</p>}
              <MultiParamSettings
                choices={spec.choices}
                value={current}
                onChange={(next) => onChange({ ...values, [spec.name]: next })}
              />
            </div>
          );
        }
        return null;
      })}
    </div>
  );
}
