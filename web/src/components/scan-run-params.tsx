import type { ToolInfo } from "@/api/types";
import { summarizeToolParams } from "@/lib/scanner-params";

export function ScanRunParams({
  runParams,
  tools,
}: {
  runParams: Record<string, Record<string, unknown>> | undefined;
  tools: ToolInfo[];
}) {
  const entries = Object.entries(runParams ?? {}).filter(([, values]) => values && Object.keys(values).length > 0);
  if (entries.length === 0) return null;

  return (
    <section className="mt-6 rounded-lg border border-ink-line bg-ink-panel/40 p-4">
      <h2 className="text-sm font-medium">Run parameters</h2>
      <p className="mt-1 text-xs text-ink-muted">Settings used when this scan started (read-only).</p>
      <ul className="mt-3 space-y-2">
        {entries.map(([name, values]) => {
          const tool = tools.find((item) => item.name === name);
          const summary = tool ? summarizeToolParams(tool, values) : JSON.stringify(values);
          return (
            <li key={name} className="rounded-md border border-ink-line/80 bg-ink-bg/60 px-3 py-2">
              <span className="font-mono text-sm">{name}</span>
              <span className="mt-0.5 block text-xs leading-5 text-ink-muted">{summary || "—"}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
