import { useQuery, useQueryClient } from "@tanstack/react-query";
import { memo, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import type { Finding, ScanEvent, Severity, TaskSummary } from "@/api/types";
import { ExplainAi } from "@/components/explain-ai";
import { ScanExportButton } from "@/components/scan-export-button";
import { ScanReportAi } from "@/components/scan-report-ai";
import { describeFindingsFilter, filterFindings, type FindingsFilterState } from "@/lib/findings-filter";
import { findingKey, FindingsTable } from "@/components/findings-table";
import { SelectMenu } from "@/components/select-menu";
import { PanelBoundary } from "@/components/panel-boundary";
import { ScanMap } from "@/components/scan-map";
import { Snippet } from "@/components/snippet";
import { Badge } from "@/components/ui/badge";
import { ScanRunParams } from "@/components/scan-run-params";
import { dismissFindings, fetchFindings, fetchLog, fetchScan, fetchTools, watchScan, type LiveChannel } from "@/lib/api";
import { elapsedSeconds, formatDuration, locationLabel } from "@/lib/utils";

const SEVERITIES: Array<Severity | "all"> = ["all", "critical", "high", "medium", "low", "info"];

function mergeLog(stored: ScanEvent[], live: ScanEvent[]): ScanEvent[] {
  const bySeq = new Map<number, ScanEvent>();
  const rest: ScanEvent[] = [];
  for (const event of [...stored, ...live]) {
    if (typeof event.seq === "number") bySeq.set(event.seq, event);
    else rest.push(event);
  }
  return [...[...bySeq.entries()].sort((left, right) => left[0] - right[0]).map((entry) => entry[1]), ...rest].slice(-400);
}

export const ScanDetailPage = memo(function ScanDetailPage({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient();
  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => fetchScan(scanId),
    refetchInterval: (query) => (query.state.data?.status === "running" ? 2000 : false),
  });
  const toolCatalog = useQuery({ queryKey: ["tools"], queryFn: fetchTools });
  const status = scan.data?.status;
  const findings = useQuery({
    queryKey: ["findings", scanId],
    queryFn: () => fetchFindings(scanId),
    refetchInterval: status === "running" ? 5000 : false,
  });
  const log = useQuery({
    queryKey: ["log", scanId],
    queryFn: () => fetchLog(scanId),
    retry: status === "running" ? 2 : 1,
    refetchInterval: status === "running" ? 2000 : false,
  });
  const [liveEvents, setLiveEvents] = useState<ScanEvent[]>([]);
  const [channel, setChannel] = useState<LiveChannel>("closed");
  const watchedLive = useRef(false);
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const [category, setCategory] = useState("all");
  const [query, setQuery] = useState("");
  const [tool, setTool] = useState("all");
  const [selected, setSelected] = useState<Finding | null>(null);
  const [checked, setChecked] = useState<Set<string>>(() => new Set());
  const [removing, setRemoving] = useState(false);
  const [removeError, setRemoveError] = useState("");

  useEffect(() => {
    if (status === "running") {
      watchedLive.current = true;
      return;
    }
    if (!watchedLive.current || (status !== "success" && status !== "failed")) return;
    watchedLive.current = false;
    void queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
    void queryClient.invalidateQueries({ queryKey: ["log", scanId] });
  }, [queryClient, scanId, status]);

  useEffect(() => {
    setLiveEvents([]);
    setSelected(null);
    setChecked(new Set());
    setRemoveError("");
    setTool("all");
    setChannel("closed");
  }, [scanId]);

  useEffect(() => {
    if (status !== "running") return;
    let alive = true;
    const stop = watchScan(
      scanId,
      (batch) => {
        if (!alive) return;
        setLiveEvents((current) => mergeLog(current, batch));
      },
      (next) => {
        if (alive) setChannel(next);
      },
    );
    return () => {
      alive = false;
      stop();
    };
  }, [scanId, status]);

  const rows = findings.data ?? [];
  const deferredRows = useDeferredValue(rows);
  const findingsFilter: FindingsFilterState = useMemo(
    () => ({ severity, category, query, tool }),
    [category, query, severity, tool],
  );
  const filteredFindingCount = useMemo(
    () => filterFindings(rows, findingsFilter).length,
    [findingsFilter, rows],
  );

  const toggleChecked = (finding: Finding, value: boolean) => {
    const key = findingKey(finding);
    setChecked((current) => {
      const next = new Set(current);
      if (value) next.add(key);
      else next.delete(key);
      return next;
    });
  };

  const toggleVisible = (visible: Finding[], value: boolean) => {
    setChecked((current) => {
      const next = new Set(current);
      for (const finding of visible) {
        const key = findingKey(finding);
        if (value) next.add(key);
        else next.delete(key);
      }
      return next;
    });
  };

  const removeChecked = async () => {
    const chosen = rows.filter((finding) => checked.has(findingKey(finding)));
    if (chosen.length === 0) return;
    setRemoving(true);
    setRemoveError("");
    try {
      await dismissFindings(scanId, chosen);
      setChecked(new Set());
      if (selected && chosen.some((finding) => findingKey(finding) === findingKey(selected))) {
        setSelected(null);
      }
      await queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      await queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
    } catch (error) {
      setRemoveError(error instanceof Error ? error.message : "Could not remove findings");
    } finally {
      setRemoving(false);
    }
  };
  const events = useMemo(() => mergeLog(log.data ?? [], liveEvents), [liveEvents, log.data]);

  useEffect(() => {
    if (status !== "running") return;
    const hasFinding = events.some((event) => event.type === "finding.accepted");
    const taskDone = events.some(
      (event) => event.type === "task.finished" && event.data?.status === "success",
    );
    if (hasFinding || taskDone) {
      void queryClient.invalidateQueries({ queryKey: ["findings", scanId] });
      void queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
    }
  }, [events, queryClient, scanId, status]);

  const showHeavy = scan.data !== undefined;
  const tableReady = !findings.isLoading || deferredRows.length > 0;
  const lastEventKey =
    events.length > 0
      ? `${events[events.length - 1]?.seq ?? "x"}:${events[events.length - 1]?.message ?? ""}`
      : "";
  const [lastEventAt, setLastEventAt] = useState(() => Date.now());
  const [progressNow, setProgressNow] = useState(() => Date.now());
  useEffect(() => {
    setLastEventAt(Date.now());
  }, [lastEventKey]);
  useEffect(() => {
    if (status !== "running") return;
    const timer = window.setInterval(() => setProgressNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [status]);
  const silentSec = status === "running" ? Math.floor((progressNow - lastEventAt) / 1000) : 0;

  return (
    <div className="px-8 py-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-ink-muted">{scanId}</p>
          <h1 className="mt-1 text-2xl font-semibold tracking-tight">{scan.data?.target_label ?? "Scan"}</h1>
          <p className="mt-1 font-mono text-xs text-ink-muted">{scan.data?.target_path}</p>
          {scan.data?.tasks && scan.data.tasks.length > 0 && (
            <p className="mt-1 font-mono text-[11px] text-ink-muted">
              {scan.data.tasks.map((task) => `${task.tool} ${formatDuration(task.duration_sec)}`).join(" · ")}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2 text-sm">
          <span className="rounded-md bg-ink-panel px-2 py-1 font-mono text-xs">{scan.data?.status ?? "…"}</span>
          <ScanClock
            status={scan.data?.status}
            createdAt={scan.data?.created_at}
            finishedAt={scan.data?.finished_at}
            fallback={scan.data?.duration_sec}
          />
          {scan.data?.partial && <span className="text-xs text-amber-200">some tasks failed</span>}
          <span className="text-xs text-ink-muted">
            raw {scan.data?.raw_total ?? 0}, excluded {scan.data?.excluded ?? 0}
          </span>
        </div>
      </div>

      {scan.data?.tasks && scan.data.tasks.length > 0 && (
        <ScanLiveTasks tasks={scan.data.tasks} running={status === "running"} />
      )}

      <ScanRunParams runParams={scan.data?.run_params} tools={toolCatalog.data ?? []} />

      <section className="mt-6">
        {status === "running" && (
          <p className="mb-2 text-xs leading-5 text-ink-muted">
            Scanners run in Docker. Heartbeats appear about every 15 seconds while a tool runs. Large projects
            (for example Juice Shop) often need several minutes per tool.
          </p>
        )}
        {status === "running" && silentSec >= 90 && (
          <p className="mb-2 text-xs text-amber-200">
            No progress for {silentSec}s. If this keeps growing, Docker may be stuck — run{" "}
            <span className="font-mono">python -m grephunt doctor</span> in the project folder.
          </p>
        )}
        <ol className="max-h-56 overflow-auto rounded-lg border border-ink-line bg-ink-panel p-3 font-mono text-xs leading-5">
          {log.isError && <li className="text-amber-200">Progress log is unavailable. Restart the console server and reload this page.</li>}
          {channel === "reconnecting" && (
            <li className="text-amber-200">Live channel dropped. Reconnecting. The saved log still updates.</li>
          )}
          {channel === "closed" && status === "running" && (
            <li className="text-amber-200">Live channel closed. The saved log is the source of progress.</li>
          )}
          {!log.isError && events.length === 0 && <li className="text-ink-muted">Waiting for scanner output</li>}
          {events.map((event, index) => (
            <li
              key={`${event.seq ?? index}-${event.type}`}
              className={event.type === "finding.accepted" ? "text-ink-text/90" : undefined}
            >
              <span className="text-ink-muted">{event.tool ? `[${event.tool}] ` : ""}</span>
              {event.type === "finding.accepted" ? (
                <span className="text-signal">{event.message}</span>
              ) : typeof event.message === "string" && event.message ? (
                event.message
              ) : (
                event.type
              )}
            </li>
          ))}
        </ol>
      </section>

      {showHeavy && (scan.data?.tasks?.length ?? 0) > 0 && (
        <div className="mt-4">
          <PanelBoundary title="Map">
            <ScanMap label={scan.data?.target_label ?? "Scan"} tasks={scan.data?.tasks ?? []} findings={deferredRows} />
          </PanelBoundary>
        </div>
      )}

      {scan.data?.error && <p className="mt-4 text-sm text-rose-300">{scan.data.error}</p>}

      <div className="mt-6 flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-wrap items-end gap-3">
        <label className="block">
          <span className="mb-1 block text-xs text-ink-muted">Search</span>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Rule, file, or CVE"
            aria-label="Search findings by rule, file, or CVE"
            className="h-9 w-72 rounded-md border border-ink-line bg-ink-bg px-3 text-sm outline-none hover:bg-ink-raised focus-visible:ring-2 focus-visible:ring-signal/60"
          />
        </label>
        <SelectMenu
          label="Severity"
          value={severity}
          onChange={setSeverity}
          emptyValue="all"
          options={SEVERITIES.map((item) => ({
            value: item,
            label: item === "all" ? "Any" : item.charAt(0).toUpperCase() + item.slice(1),
          }))}
        />
        <SelectMenu
          label="Category"
          value={category}
          onChange={setCategory}
          emptyValue="all"
          options={[
            { value: "all", label: "Any" },
            { value: "code", label: "Code" },
            { value: "secret", label: "Secret" },
            { value: "dependency", label: "Dependency" },
            { value: "misconfig", label: "Misconfig" },
          ]}
        />
        <SelectMenu
          label="Tool"
          value={tool}
          onChange={setTool}
          emptyValue="all"
          options={[
            { value: "all", label: "Any" },
            ...[
              ...new Set(
                [
                  ...(scan.data?.tasks ?? []).map((task) => task.tool),
                  ...rows.flatMap((item) => [item.tool, ...(item.tools ?? [])]),
                ].filter(Boolean),
              ),
            ]
              .sort((left, right) => left.localeCompare(right))
              .map((name) => ({ value: name.toLowerCase(), label: name })),
          ]}
        />
        </div>
        <ScanReportAi scan={scan.data} findings={rows} />
      </div>

      <div className="mt-3 grid items-start gap-4 xl:grid-cols-[1fr_320px]">
        <div className="min-w-0">
          <div className="mb-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-ink-line bg-ink-panel px-4 py-3">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold tracking-tight text-ink-text">Findings report</h2>
              <p className="mt-0.5 text-xs text-ink-muted">
                {rows.length === 0
                  ? "No findings yet"
                  : describeFindingsFilter(findingsFilter, rows.length, filteredFindingCount)}
                {rows.length > 0 && " · Markdown export includes metadata, summary, and evidence snippets"}
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={removing || checked.size === 0}
                onClick={() => void removeChecked()}
                className="inline-flex h-9 items-center justify-center rounded-md border border-rose-500/40 bg-ink-panel px-3.5 text-sm font-medium text-rose-100 hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {removing ? "Removing…" : checked.size > 0 ? `Remove ${checked.size}` : "Remove"}
              </button>
              <ScanExportButton scan={scan.data} findings={rows} filter={findingsFilter} />
            </div>
          </div>
          {removeError && <p className="mb-3 text-xs text-rose-200">{removeError}</p>}
        <PanelBoundary title="Findings">
          {findings.isLoading && rows.length === 0 ? (
            <p className="rounded-lg border border-ink-line px-3 py-8 text-sm text-ink-muted">Loading findings…</p>
          ) : tableReady ? (
            <FindingsTable
              findings={deferredRows}
              severity={severity}
              category={category}
              query={query}
              tool={tool}
              selected={selected}
              onSelect={setSelected}
              checked={checked}
              onToggle={toggleChecked}
              onToggleVisible={toggleVisible}
            />
          ) : (
            <p className="rounded-lg border border-ink-line px-3 py-8 text-sm text-ink-muted">Preparing table…</p>
          )}
        </PanelBoundary>
        </div>
        <aside className="rounded-lg border border-ink-line bg-ink-panel p-4">
          {selected ? <FindingDetail finding={selected} /> : <p className="text-sm text-ink-muted">Select a row to see the evidence.</p>}
        </aside>
      </div>
    </div>
  );
});

function taskStatusText(task: TaskSummary): string {
  if (task.status === "success") return "finished";
  if (task.status === "failed") return "failed";
  if (task.status === "timeout") return "timed out";
  if (task.status === "skipped") return "skipped";
  if (task.status === "queued") return "queued";
  return "running";
}

function ScanLiveTasks({ tasks, running }: { tasks: TaskSummary[]; running: boolean }) {
  return (
    <div className="mt-6 grid gap-2 sm:grid-cols-2">
      {tasks.map((task) => {
        const active = running && (task.status === "running" || task.status === "queued");
        return (
          <div key={task.tool} className="rounded-lg border border-ink-line bg-ink-panel px-3 py-2">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm">{task.tool}</span>
              {active && (
                <span
                  className="size-2 shrink-0 animate-pulse rounded-full bg-signal"
                  title="Scanner reported progress recently"
                />
              )}
            </div>
            <p className="mt-1 font-mono text-[11px] capitalize text-ink-muted">{taskStatusText(task)}</p>
            {active && (
              <p className="mt-0.5 font-mono text-[11px] text-signal">{formatDuration(task.duration_sec)} elapsed</p>
            )}
            {task.error && <p className="mt-1 line-clamp-2 text-[11px] text-rose-300">{task.error}</p>}
          </div>
        );
      })}
    </div>
  );
}

function ScanClock({
  status,
  createdAt,
  finishedAt,
  fallback,
}: {
  status?: string;
  createdAt?: string | null;
  finishedAt?: string | null;
  fallback?: number | null;
}) {
  const [now, setNow] = useState(() => Date.now());
  const running = status === "running";
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);
  const duration = running
    ? elapsedSeconds(createdAt, null, now)
    : finishedAt
      ? elapsedSeconds(createdAt, finishedAt)
      : (fallback ?? null);
  if (duration == null) return null;
  return (
    <span className="rounded-md bg-ink-panel px-2 py-1 font-mono text-xs text-signal" title="Wall-clock scan time">
      {formatDuration(duration)}
    </span>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  const cwe = finding.cwe ?? [];
  const cve = finding.cve ?? [];
  return (
    <div className="space-y-3">
      <Badge tone={finding.severity}>{finding.severity}</Badge>
      <h2 className="text-sm font-medium leading-5">{finding.title}</h2>
      {finding.location && (
        <p className="font-mono text-xs text-ink-muted">{locationLabel(finding.location)}</p>
      )}
      {finding.snippet && <Snippet code={finding.snippet} path={finding.location?.path ?? null} />}
      <dl className="space-y-1 font-mono text-[11px] leading-5 text-ink-muted">
        <div>fingerprint {finding.fingerprint}</div>
        <div>correlation {finding.correlation_key}</div>
        <div>module {finding.module}</div>
        {cwe.length > 0 && <div>{cwe.join(", ")}</div>}
        {cve.length > 0 && <div>{cve.join(", ")}</div>}
        {finding.fixed_version && <div>fix {finding.fixed_version}</div>}
        {finding.raw_ref && <div>raw {finding.raw_ref}</div>}
        {finding.severity_original && <div>original severity {finding.severity_original}</div>}
      </dl>
      {finding.message && <p className="whitespace-pre-wrap break-words text-xs leading-5 text-ink-text/90">{finding.message}</p>}
      <ExplainAi finding={finding} />
    </div>
  );
}
