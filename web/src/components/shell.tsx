import { useQuery } from "@tanstack/react-query";
import { Crosshair, SlidersHorizontal } from "lucide-react";
import { useState, type ReactNode } from "react";
import { fetchScans } from "@/lib/api";
import { onSameTabClick, scanIdFromPath, useNavigation } from "@/lib/nav";
import { formatDuration } from "@/lib/utils";
import type { ScanSummary } from "@/api/types";
import { CommandPalette } from "@/components/command-palette";

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
  const [palette, setPalette] = useState(false);

  return (
    <div className="flex min-h-screen">
      <aside className="flex w-60 shrink-0 flex-col border-r border-ink-line bg-ink-panel">
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
        <nav className="flex-1 overflow-auto px-2">
          {(scans.data ?? []).map((scan) => (
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
        </nav>
        <button
          type="button"
          aria-label="Open quick commands"
          title="Open commands for a new scan"
          onClick={() => setPalette(true)}
          className="m-3 flex items-start gap-2 rounded-md border border-ink-line px-2.5 py-2 text-left hover:bg-ink-raised"
        >
          <SlidersHorizontal className="mt-0.5 size-4 shrink-0 text-ink-muted" aria-hidden="true" />
          <span>
            <span className="block text-sm text-ink-text">Quick commands</span>
            <span className="block text-[11px] leading-4 text-ink-muted">New scan and navigation</span>
          </span>
        </button>
      </aside>
      <main className="min-w-0 flex-1">{children}</main>
      <CommandPalette open={palette} onOpenChange={setPalette} />
    </div>
  );
}
