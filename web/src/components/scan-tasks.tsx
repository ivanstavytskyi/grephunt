import { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Cloud, Container, Filter } from "lucide-react";
import type { ScanEvent, Severity, TaskSummary } from "@/api/types";
import { cn, elapsedSeconds, formatDuration } from "@/lib/utils";

const PHASES = ["queued", "image", "prepare", "start", "scan", "parse", "done"] as const;
const PHASE_LABEL: Record<string, string> = {
  queued: "Queued",
  check: "Check",
  image: "Image",
  prepare: "Prepare",
  start: "Container",
  scan: "Scanning",
  parse: "Parsing",
  done: "Done",
};
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_TONE: Record<Severity, string> = {
  critical: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  high: "bg-orange-500/15 text-orange-300 ring-orange-500/30",
  medium: "bg-amber-400/15 text-amber-200 ring-amber-400/30",
  low: "bg-zinc-500/15 text-zinc-300 ring-zinc-500/30",
  info: "bg-sky-500/15 text-sky-300 ring-sky-500/30",
};
const STATUS_TONE: Record<string, string> = {
  running: "bg-signal/15 text-signal ring-signal/40",
  queued: "bg-zinc-500/15 text-zinc-300 ring-zinc-500/30",
  success: "bg-emerald-500/15 text-emerald-300 ring-emerald-500/30",
  failed: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  timeout: "bg-rose-500/15 text-rose-300 ring-rose-500/30",
  skipped: "bg-zinc-500/10 text-ink-muted ring-ink-line",
};
const STATUS_LABEL: Record<string, string> = {
  running: "running",
  queued: "queued",
  success: "finished",
  failed: "failed",
  timeout: "timed out",
  skipped: "skipped",
};
const ORDER: Record<string, number> = { running: 0, queued: 1, failed: 2, timeout: 2, success: 3, skipped: 4 };
const CONTAINER_TONE: Record<string, string> = {
  starting: "text-amber-200",
  created: "text-amber-200",
  running: "text-signal",
  exited: "text-ink-muted",
  killed: "text-rose-300",
  failed: "text-rose-300",
  dead: "text-rose-300",
};

function bytes(value: number | undefined): string {
  if (value == null) return "";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1024 / 1024).toFixed(1)} MB`;
}

function sumCounts(counts: Partial<Record<Severity, number>> | undefined): number {
  return Object.values(counts ?? {}).reduce((total, value) => total + (value ?? 0), 0);
}

function ago(at: string | undefined, now: number): string {
  if (!at) return "";
  const seconds = elapsedSeconds(at, null, now);
  if (seconds == null) return "";
  return seconds < 2 ? "just now" : `${formatDuration(seconds)} ago`;
}

function SeverityChips({ counts }: { counts: Partial<Record<Severity, number>> | undefined }) {
  const present = SEVERITIES.filter((severity) => (counts?.[severity] ?? 0) > 0);
  if (present.length === 0) return <span className="text-ink-muted">none</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {present.map((severity) => (
        <span
          key={severity}
          title={severity}
          className={cn("rounded px-1.5 py-px font-mono text-[10px] uppercase ring-1 ring-inset", SEV_TONE[severity])}
        >
          {severity.slice(0, 4)} {counts?.[severity]}
        </span>
      ))}
    </span>
  );
}

function PhaseStepper({ task }: { task: TaskSummary }) {
  const details = task.details ?? {};
  const failed = task.status === "failed" || task.status === "timeout";
  const skipped = task.status === "skipped";
  const current = failed ? details.failed_phase ?? details.phase : details.phase ?? (task.status === "queued" ? "queued" : undefined);
  const currentIndex = task.status === "success" ? PHASES.length - 1 : PHASES.indexOf((current ?? "queued") as (typeof PHASES)[number]);
  const reached = new Set((details.timeline ?? []).map((item) => item.phase));
  return (
    <div className="mt-2 flex items-center gap-1" aria-label={`Stage: ${PHASE_LABEL[current ?? ""] ?? current ?? "unknown"}`}>
      {PHASES.map((phase, index) => {
        const isCurrent = index === currentIndex && task.status !== "success";
        const done = index < currentIndex || task.status === "success";
        const wasSkipped = done && !reached.has(phase) && phase !== "done" && phase !== "queued" && (details.timeline?.length ?? 0) > 0;
        return (
          <div key={phase} className="flex min-w-0 flex-1 flex-col items-center gap-1" title={PHASE_LABEL[phase]}>
            <div
              className={cn(
                "h-1.5 w-full rounded-full",
                skipped
                  ? "bg-ink-line"
                  : isCurrent && failed
                    ? "bg-rose-400"
                    : isCurrent
                      ? "animate-pulse bg-signal"
                      : done && !wasSkipped
                        ? "bg-emerald-400/70"
                        : done
                          ? "bg-ink-line"
                          : "bg-ink-raised",
              )}
            />
            <span
              className={cn(
                "truncate text-[9px] uppercase tracking-wide",
                isCurrent ? (failed ? "text-rose-300" : "text-signal") : "text-ink-muted/70",
              )}
            >
              {PHASE_LABEL[phase]}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex min-w-0 items-start gap-2">
      <dt className="w-20 shrink-0 text-ink-muted">{label}</dt>
      <dd className="min-w-0 flex-1 break-words text-ink-text/90">{children}</dd>
    </div>
  );
}

function TaskCard({
  task,
  events,
  running,
  now,
  onShowFindings,
}: {
  task: TaskSummary;
  events: ScanEvent[];
  running: boolean;
  now: number;
  onShowFindings?: (tool: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const details = task.details ?? {};
  const container = details.container ?? {};
  const active = running && (task.status === "running" || task.status === "queued");
  const elapsed = details.started_at
    ? elapsedSeconds(details.started_at, details.finished_at ?? (active ? null : details.last_event_at), now)
    : task.duration_sec;
  const reported = details.raw_findings;
  const accepted = details.accepted;
  const inReport = sumCounts(task.report_findings);
  const limits = task.limits ?? {};
  const toolEvents = events.filter((event) => event.tool === task.tool && event.type !== "finding.accepted").slice(-25);
  const timeline = details.timeline ?? [];

  return (
    <div
      className={cn(
        "rounded-lg border bg-ink-panel px-3 py-2.5",
        task.status === "failed" || task.status === "timeout" ? "border-rose-500/40" : active ? "border-signal/40" : "border-ink-line",
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate font-mono text-sm">{task.tool}</span>
          {task.tool_version && <span className="font-mono text-[10px] text-ink-muted">v{task.tool_version}</span>}
          {(details.cloud || limits.cloud) && (
            <span title="Runs in the vendor's cloud: project data leaves this machine" className="inline-flex text-sky-300">
              <Cloud className="size-3.5" aria-hidden="true" />
              <span className="sr-only">cloud scanner</span>
            </span>
          )}
        </div>
        <span
          className={cn(
            "shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] uppercase ring-1 ring-inset",
            STATUS_TONE[task.status] ?? STATUS_TONE.queued,
          )}
        >
          {STATUS_LABEL[task.status] ?? task.status}
        </span>
      </div>

      <PhaseStepper task={task} />

      <dl className="mt-2 space-y-1 font-mono text-[11px] leading-4">
        <Row label="time">
          <span className={active ? "text-signal" : undefined}>{formatDuration(elapsed) || "—"}</span>
          {details.run_sec != null && <span className="text-ink-muted"> · scan {formatDuration(details.run_sec)}</span>}
          {(details.timeout_sec ?? limits.timeout_sec) && (
            <span className="text-ink-muted"> · limit {formatDuration(details.timeout_sec ?? limits.timeout_sec)}</span>
          )}
        </Row>
        <Row label="findings">
          {reported == null ? (
            <span className="text-ink-muted">{task.status === "success" ? "0" : "—"}</span>
          ) : (
            <span className="flex flex-col gap-1">
              <span>
                {reported} reported · {accepted ?? reported} after filters
                {inReport > 0 && <span className="text-ink-muted"> · {inReport} in report</span>}
              </span>
              <SeverityChips counts={details.severities ?? details.raw_severities} />
            </span>
          )}
        </Row>
        {(details.mode === "docker" || container.name) && (
          <Row label="docker">
            <span className="inline-flex items-center gap-1">
              <Container className="size-3 text-ink-muted" aria-hidden="true" />
              <span className={CONTAINER_TONE[container.status ?? ""] ?? "text-ink-muted"}>
                {container.status ?? (task.status === "queued" ? "not started" : "—")}
              </span>
              {container.exit_code != null && <span className="text-ink-muted">(exit {container.exit_code})</span>}
            </span>
            {container.status === "running" && (container.cpu || container.memory) && (
              <span className="block text-ink-muted">
                {container.cpu && `CPU ${container.cpu}`}
                {container.memory && ` · mem ${container.memory}`}
                {container.pids && ` · ${container.pids} pids`}
              </span>
            )}
          </Row>
        )}
        {details.mode === "local" && <Row label="mode">local binary {details.binary && <span className="text-ink-muted">{details.binary}</span>}</Row>}
        {(details.image || task.image) && details.mode !== "local" && (
          <Row label="image">
            <span className="text-ink-muted">{details.image ?? task.image}</span>
            {details.pulled != null && (
              <span className={details.pulled ? "text-amber-200" : "text-ink-muted"}>
                {" "}
                · {details.pulled ? `pulled ${formatDuration(details.pull_sec ?? 0)}` : "cached"}
              </span>
            )}
          </Row>
        )}
        {details.exit_code != null && details.mode !== "docker" && <Row label="exit">{details.exit_code}</Row>}
        {details.last_message && task.status !== "success" && (
          <Row label="last">
            <span className="line-clamp-2">{details.last_message}</span>
            <span className="text-ink-muted"> {ago(details.last_event_at, now)}</span>
          </Row>
        )}
      </dl>

      {task.error && task.status !== "skipped" && (
        <p className="mt-1.5 line-clamp-3 text-[11px] text-rose-300" title={task.error}>
          {details.failed_phase && <span className="font-mono">[{PHASE_LABEL[details.failed_phase] ?? details.failed_phase}] </span>}
          {task.error}
        </p>
      )}
      {task.status === "skipped" && task.error && <p className="mt-1.5 text-[11px] text-ink-muted">{task.error}</p>}

      <div className="mt-2 flex items-center gap-3">
        <button
          type="button"
          onClick={() => setOpen((value) => !value)}
          aria-expanded={open}
          className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-ink-text"
        >
          {open ? <ChevronDown className="size-3" /> : <ChevronRight className="size-3" />}
          Details
        </button>
        {onShowFindings && (inReport > 0 || (accepted ?? 0) > 0) && (
          <button
            type="button"
            onClick={() => onShowFindings(task.tool.toLowerCase())}
            className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-signal"
          >
            <Filter className="size-3" />
            Show findings
          </button>
        )}
      </div>

      {open && (
        <div className="mt-2 space-y-2 border-t border-ink-line pt-2 font-mono text-[11px] leading-4">
          <dl className="space-y-1">
            {container.name && <Row label="container">{container.name}</Row>}
            {(container.cpus_limit || limits.cpus) && (
              <Row label="limits">
                {container.cpus_limit ?? limits.cpus} CPU · {container.memory_limit ?? limits.memory} ·{" "}
                {container.pids_limit ?? limits.pids_limit} pids
              </Row>
            )}
            {container.network && <Row label="network">{container.network}</Row>}
            {container.user && <Row label="user">{container.user}</Row>}
            {container.net_io && <Row label="net I/O">{container.net_io}</Row>}
            {container.block_io && <Row label="disk I/O">{container.block_io}</Row>}
            {limits.module && <Row label="module">{limits.module}{limits.category ? ` · ${limits.category}` : ""}</Row>}
            {details.rules != null && <Row label="rules hit">{details.rules} rules in {details.files ?? 0} files</Row>}
            {details.sarif_bytes != null && <Row label="SARIF">{bytes(details.sarif_bytes)}</Row>}
            {(details.stdout_bytes != null || details.stderr_bytes != null) && (
              <Row label="output">stdout {bytes(details.stdout_bytes)} · stderr {bytes(details.stderr_bytes)}</Row>
            )}
          </dl>
          {timeline.length > 0 && (
            <div>
              <p className="mb-1 text-ink-muted">Stages</p>
              <ol className="space-y-0.5">
                {timeline.map((item, index) => {
                  const next = timeline[index + 1]?.at ?? (active ? null : details.finished_at ?? details.last_event_at);
                  const spent = elapsedSeconds(item.at, next, now);
                  return (
                    <li key={`${item.phase}-${index}`} className="flex justify-between gap-2">
                      <span>{PHASE_LABEL[item.phase] ?? item.phase}</span>
                      <span className="text-ink-muted">{item.phase === "done" ? new Date(item.at).toLocaleTimeString() : formatDuration(spent)}</span>
                    </li>
                  );
                })}
              </ol>
            </div>
          )}
          {toolEvents.length > 0 && (
            <div>
              <p className="mb-1 text-ink-muted">Log</p>
              <ol className="max-h-40 space-y-0.5 overflow-auto text-ink-text/80">
                {toolEvents.map((event, index) => (
                  <li key={`${event.seq ?? index}`}>{event.message || event.type}</li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function ScanTasks({
  tasks,
  events,
  running,
  onShowFindings,
}: {
  tasks: TaskSummary[];
  events: ScanEvent[];
  running: boolean;
  onShowFindings?: (tool: string) => void;
}) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  const sorted = useMemo(
    () => [...tasks].sort((left, right) => (ORDER[left.status] ?? 5) - (ORDER[right.status] ?? 5) || left.tool.localeCompare(right.tool)),
    [tasks],
  );
  const counts = useMemo(() => {
    const result: Record<string, number> = {};
    for (const task of tasks) result[task.status] = (result[task.status] ?? 0) + 1;
    return result;
  }, [tasks]);
  const finished = tasks.filter((task) => !["running", "queued"].includes(task.status)).length;
  const reportedTotal = tasks.reduce((total, task) => total + (task.details?.raw_findings ?? 0), 0);
  const acceptedTotal = tasks.reduce((total, task) => total + (task.details?.accepted ?? 0), 0);
  const containers = tasks.filter((task) => task.details?.container?.status === "running").length;
  const progress = tasks.length ? Math.round((finished / tasks.length) * 100) : 0;

  return (
    <section className="mt-6">
      <div className="rounded-lg border border-ink-line bg-ink-panel px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-semibold text-ink-text">Scanners</span>
            <span className="font-mono text-ink-muted">
              {finished}/{tasks.length} done
            </span>
            {Object.entries(counts)
              .sort((left, right) => (ORDER[left[0]] ?? 5) - (ORDER[right[0]] ?? 5))
              .map(([status, count]) => (
                <span
                  key={status}
                  className={cn("rounded px-1.5 py-0.5 font-mono text-[10px] uppercase ring-1 ring-inset", STATUS_TONE[status] ?? STATUS_TONE.queued)}
                >
                  {STATUS_LABEL[status] ?? status} {count}
                </span>
              ))}
          </div>
          <div className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-ink-muted">
            {running && <span>{containers} containers running</span>}
            <span>
              {reportedTotal} reported · <span className="text-ink-text">{acceptedTotal}</span> after filters
            </span>
          </div>
        </div>
        <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-ink-raised">
          <div className="h-full bg-signal transition-all" style={{ width: `${progress}%` }} />
        </div>
      </div>
      <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
        {sorted.map((task) => (
          <TaskCard key={task.tool} task={task} events={events} running={running} now={now} onShowFindings={onShowFindings} />
        ))}
      </div>
    </section>
  );
}
