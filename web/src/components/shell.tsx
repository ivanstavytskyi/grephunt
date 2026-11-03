import { useQuery } from "@tanstack/react-query";
import { Crosshair, Search } from "lucide-react";
import { useState, type ReactNode } from "react";
import { fetchScans } from "@/lib/api";
import { onSameTabClick, scanIdFromPath, useNavigation } from "@/lib/nav";
import { formatDuration } from "@/lib/utils";
import type { ScanSummary } from "@/api/types";

function scanDetails(scan: ScanSummary): string {
  const when = scan.finished_at ?? scan.created_at;
  const stamp = when ? new Date(when).toLocaleString() : "time unknown";
  const moment = scan.status === "running" ? `Started ${stamp}` : `Finished ${stamp}`;
  const duration = scan.duration_sec != null ? `Duration ${formatDuration(scan.duration_sec)}` : "";
  const findings = `${scan.finding_count} findings`;
  return [scan.target_label, scan.status, moment, duration, findings].filter(Boolean).join(". ");
}

export function Shell({ children }: { children: ReactNode }) {
  const { path, navigate } = useNavigation();
  const openScan = scanIdFromPath(path);
  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: fetchScans,
    refetchInterval: (query) => ((query.state.data ?? []).some((scan) => scan.status === "running") ? 4000 : 15000),
  });
  const [filter, setFilter] = useState("");
  const needle = filter.trim().toLowerCase();
  const list = (scans.data ?? []).filter((scan) => !needle || scan.target_label.toLowerCase().includes(needle));

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-ink-line bg-ink-panel">
        <a
          href="/"
          aria-label="GrepHunt, new scan"
          className="flex items-center gap-2 px-4 py-4"
          onClick={(event) => onSameTabClick(event, navigate, "/")}
        >
          <Crosshair className="size-4 text-signal" aria-hidden="true" />
          <span className="text-sm font-semibold tracking-tight">GrepHunt</span>
        </a>
        <p className="px-4 pb-2 text-[11px] uppercase tracking-wider text-ink-muted">Scans</p>
        {(scans.data?.length ?? 0) > 5 && (
          <label className="mx-3 mb-2 flex h-8 items-center gap-1.5 rounded-md border border-ink-line px-2 text-ink-muted focus-within:border-ink-muted">
            <Search className="size-3.5 shrink-0" aria-hidden="true" />
            <input
              value={filter}
              onChange={(event) => setFilter(event.target.value)}
              placeholder="Find a scan"
              aria-label="Find a scan by name"
              className="min-w-0 flex-1 bg-transparent text-xs text-ink-text outline-none placeholder:text-ink-muted"
            />
          </label>
        )}
        <nav className="flex-1 overflow-auto px-2">
          {list.map((scan) => (
            <a
              key={scan.id}
              href={`/scans/${scan.id}`}
              aria-label={scanDetails(scan)}
              title={scanDetails(scan)}
              aria-current={openScan === scan.id ? "page" : undefined}
              onClick={(event) => onSameTabClick(event, navigate, `/scans/${scan.id}`)}
              className={`mb-1 block w-full rounded-md px-2 py-2 text-left hover:bg-ink-raised ${openScan === scan.id ? "bg-ink-raised" : ""}`}
            >
              <span className="block truncate text-sm">{scan.target_label}</span>
              <span className="font-mono text-[11px] text-ink-muted">
                {scan.status}
                {scan.duration_sec != null ? ` · ${formatDuration(scan.duration_sec)}` : ""}
                {scan.finding_count ? ` · ${scan.finding_count}` : ""}
              </span>
            </a>
          ))}
          {scans.data?.length === 0 && <p className="px-2 text-sm text-ink-muted">Nothing yet</p>}
          {needle && list.length === 0 && <p className="px-2 text-xs text-ink-muted">No scan matches</p>}
        </nav>
      </aside>
      <main className="min-w-0 flex-1">{children}</main>
    </div>
  );
}
