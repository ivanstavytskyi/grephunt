import type { Finding, FindingTier } from "@/api/types";

export type TierChoice = FindingTier | "all";

export const TIER_TABS: { id: TierChoice; label: string; hint: string }[] = [
  { id: "main", label: "Main", hint: "What to look at first" },
  { id: "review", label: "Needs review", hint: "Reported, but the strongest check for this code did not back it" },
  { id: "not_executed", label: "Not executed", hint: "Code the application never imports, links or loads" },
  { id: "hygiene", label: "Hygiene", hint: "Informational notes that are not vulnerabilities" },
  { id: "infra", label: "Infra & CI", hint: "Infrastructure as code and CI pipeline findings" },
  { id: "all", label: "All", hint: "Every finding in the scan" },
];

export function tierOf(finding: Finding): FindingTier {
  return finding.tier ?? "main";
}

export function filterByTier(rows: Finding[], tier: TierChoice): Finding[] {
  return tier === "all" ? rows : rows.filter((finding) => tierOf(finding) === tier);
}

export function FindingTiers({
  rows,
  value,
  onChange,
}: {
  rows: Finding[];
  value: TierChoice;
  onChange: (next: TierChoice) => void;
}) {
  const counts = new Map<TierChoice, number>([["all", rows.length]]);
  for (const finding of rows) {
    const tier = tierOf(finding);
    counts.set(tier, (counts.get(tier) ?? 0) + 1);
  }
  return (
    <div role="tablist" aria-label="Finding groups" className="mb-3 flex flex-wrap gap-1.5">
      {TIER_TABS.map((tab) => {
        const count = counts.get(tab.id) ?? 0;
        if (tab.id !== "main" && tab.id !== "all" && count === 0) return null;
        const active = value === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active}
            title={tab.hint}
            onClick={() => onChange(tab.id)}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-3 text-xs ${
              active
                ? "border-signal/60 bg-signal/10 text-ink-text"
                : "border-ink-line text-ink-muted hover:bg-ink-raised hover:text-ink-text"
            }`}
          >
            {tab.label}
            <span className="font-mono tabular-nums opacity-80">{count}</span>
          </button>
        );
      })}
    </div>
  );
}
