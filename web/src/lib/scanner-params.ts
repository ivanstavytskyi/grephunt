import type { ToolInfo, ToolParameterSpec } from "@/api/types";

export type ToolParamsState = Record<string, Record<string, unknown>>;

export function defaultToolParams(specs: ToolParameterSpec[]): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const spec of specs) {
    if (spec.type === "bool") {
      values[spec.name] = spec.default === true;
    } else if (spec.default !== undefined && spec.default !== null) {
      if (spec.type === "multi" || spec.type === "string_list") {
        values[spec.name] = Array.isArray(spec.default) ? [...spec.default] : [];
      } else {
        values[spec.name] = spec.default;
      }
    } else if (spec.type === "multi") {
      values[spec.name] = [...spec.choices];
    } else if (spec.type === "string_list") {
      values[spec.name] = [];
    } else {
      values[spec.name] = "";
    }
  }
  return values;
}

export function buildInitialParams(tools: ToolInfo[]): ToolParamsState {
  const state: ToolParamsState = {};
  for (const tool of tools) {
    if (tool.parameters?.length) {
      state[tool.name] = defaultToolParams(tool.parameters);
    }
  }
  return state;
}

function stable(value: unknown): string {
  return JSON.stringify(value);
}

export function paramsDifferFromDefaults(tool: ToolInfo, values: Record<string, unknown> | undefined): boolean {
  if (!tool.parameters?.length || !values) return false;
  const defaults = defaultToolParams(tool.parameters);
  for (const spec of tool.parameters) {
    if (stable(values[spec.name]) !== stable(defaults[spec.name])) return true;
  }
  return false;
}

export function summarizeToolParams(tool: ToolInfo, values: Record<string, unknown> | undefined): string {
  if (!tool.parameters?.length || !values) return "";
  const parts: string[] = [];
  for (const spec of tool.parameters) {
    const value = values[spec.name];
    if (spec.type === "multi" && Array.isArray(value)) {
      parts.push((value as string[]).join(", "));
    } else if (spec.type === "string_list" && Array.isArray(value)) {
      const list = value as string[];
      const head = list.slice(0, 2).join(", ");
      parts.push(list.length > 2 ? `${head}…` : head);
    } else if (typeof value === "string" && value.trim()) {
      parts.push(value.trim());
    }
  }
  return parts.join(" · ");
}

export function paramsForScanners(
  selected: string[],
  tools: ToolInfo[],
  state: ToolParamsState,
): Record<string, Record<string, unknown>> {
  const payload: Record<string, Record<string, unknown>> = {};
  for (const name of selected) {
    const tool = tools.find((item) => item.name === name);
    if (!tool?.parameters?.length) continue;
    payload[name] = { ...state[name] };
  }
  return payload;
}
