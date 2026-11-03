import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Maximize2, X } from "lucide-react";
import type { Finding, Severity, SourceMark, SourceMarkKind, SourceView } from "@/api/types";
import { fetchSource } from "@/lib/api";
import { cn } from "@/lib/utils";

const FOCUS_TONE: Record<Severity, string> = {
  critical: "bg-rose-500/15 border-rose-400",
  high: "bg-orange-500/15 border-orange-400",
  medium: "bg-amber-400/12 border-amber-300",
  low: "bg-zinc-400/10 border-zinc-400",
  info: "bg-sky-500/10 border-sky-400",
};

const MARK_TONE: Record<SourceMarkKind, string> = {
  finding: "bg-orange-500/15 text-orange-200 ring-orange-500/30",
  input: "bg-sky-500/15 text-sky-200 ring-sky-500/30",
  route: "bg-violet-500/15 text-violet-200 ring-violet-500/30",
  sink: "bg-rose-500/15 text-rose-200 ring-rose-500/30",
  call: "bg-emerald-500/15 text-emerald-200 ring-emerald-500/30",
};

const MARK_NAME: Record<SourceMarkKind, string> = {
  finding: "finding",
  input: "input",
  route: "route",
  sink: "sink",
  call: "call",
};

const KEYWORDS = new Set(
  (
    "if else elif for while return function def class import from export const let var new try catch except finally " +
    "throw raise async await public private protected static final void package func go defer select case switch " +
    "break continue default with as in of null None true false True False nil this self echo require include resource " +
    "variable module provider data locals output"
  ).split(" "),
);

const TOKEN = /(\/\/.*$|#.*$|--\s.*$|\/\*.*?\*\/|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\b[A-Za-z_$][\w$]*\b|\b\d+(?:\.\d+)?\b)/g;

function highlight(line: string, language: string | null): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  const hashComments = language !== "javascript" && language !== "typescript" && language !== "java" && language !== "go";
  for (const match of line.matchAll(TOKEN)) {
    const token = match[0];
    const index = match.index ?? 0;
    if (index > last) out.push(line.slice(last, index));
    let tone = "";
    if (token.startsWith("#") && !hashComments) {
      out.push(token);
      last = index + token.length;
      continue;
    }
    if (token.startsWith("//") || token.startsWith("/*") || token.startsWith("#") || token.startsWith("-- ")) {
      out.push(<span key={index} className="text-zinc-500">{line.slice(index)}</span>);
      return out;
    }
    if (/^["'`]/.test(token)) tone = "text-emerald-300/90";
    else if (/^\d/.test(token)) tone = "text-amber-200/90";
    else if (KEYWORDS.has(token)) tone = "text-violet-300";
    out.push(tone ? <span key={index} className={tone}>{token}</span> : token);
    last = index + token.length;
  }
  if (last < line.length) out.push(line.slice(last));
  return out;
}

function MarkChip({ mark, wrap = false }: { mark: SourceMark; wrap?: boolean }) {
  return (
    <span className={cn("inline-flex min-w-0 max-w-full items-start gap-1 rounded px-1.5 py-0.5 font-sans text-[11px] leading-4 ring-1 ring-inset", MARK_TONE[mark.kind])}>
      <span className="shrink-0 font-mono uppercase tracking-wide opacity-70">{mark.kind === "finding" && mark.severity ? mark.severity : MARK_NAME[mark.kind]}</span>
      <span className={wrap ? "break-words" : "truncate"}>{mark.label}</span>
    </span>
  );
}

function SourceLines({ view, finding, compact }: { view: SourceView; finding: Finding; compact: boolean }) {
  const focusRef = useRef<HTMLDivElement | null>(null);
  const marksByLine = useMemo(() => {
    const map = new Map<number, SourceMark[]>();
    for (const mark of view.marks) {
      const isSelf =
        mark.kind === "finding" && mark.fingerprint === finding.fingerprint && mark.correlation_key === finding.correlation_key;
      if (isSelf) continue;
      map.set(mark.line, [...(map.get(mark.line) ?? []), mark]);
    }
    return map;
  }, [view.marks, finding.fingerprint, finding.correlation_key]);

  useEffect(() => {
    focusRef.current?.scrollIntoView({ block: "center" });
  }, [view]);

  const width = String(view.start + view.lines.length).length;
  return (
    <div className={cn("overflow-auto rounded-md border border-ink-line bg-black/30 font-mono text-xs leading-5", compact ? "max-h-72" : "h-full")}>
      {view.lines.map((text, index) => {
        const number = view.start + index;
        const inFocus = number >= view.focus.start && number <= view.focus.end;
        const marks = marksByLine.get(number) ?? [];
        return (
          <div key={number} id={`L${number}`} ref={number === view.focus.start ? focusRef : undefined}>
            <div className={cn("flex border-l-2 border-transparent", inFocus && FOCUS_TONE[finding.severity])}>
              <span className="sticky left-0 shrink-0 select-none bg-ink-panel/80 px-2 text-right text-zinc-500" style={{ minWidth: `${width + 2}ch` }}>
                {number}
              </span>
              <span className="w-3 shrink-0 select-none text-center">
                {marks.length > 0 && <span className={cn("inline-block size-1.5 rounded-full", marks[0].kind === "sink" ? "bg-rose-400" : marks[0].kind === "input" ? "bg-sky-400" : marks[0].kind === "route" ? "bg-violet-400" : marks[0].kind === "call" ? "bg-emerald-400" : "bg-orange-400")} />}
              </span>
              <code className="whitespace-pre pr-4 text-ink-text">{highlight(text, view.language)}</code>
            </div>
            {number === view.focus.end && (
              <div className="ml-[calc(var(--gutter)+0.75rem)] border-l-2 border-transparent py-1 pl-2 pr-3" style={{ ["--gutter" as string]: `${width + 2}ch` }}>
                <div className={cn("rounded-md px-2 py-1.5 font-sans text-[11px] leading-4 ring-1 ring-inset", MARK_TONE.finding)}>
                  <span className="font-medium">{finding.title}</span>
                  {finding.rule_id && <span className="ml-1 font-mono opacity-70">{finding.rule_id}</span>}
                </div>
              </div>
            )}
            {marks.length > 0 && !compact && (
              <div className="flex flex-wrap gap-1 py-0.5 pr-3" style={{ paddingLeft: `calc(${width + 2}ch + 1.25rem)` }}>
                {marks.map((mark, markIndex) => (
                  <MarkChip key={markIndex} mark={mark} />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function useSource(scanId: string, finding: Finding, context: number, enabled = true) {
  const location = finding.location;
  return useQuery({
    queryKey: ["source", scanId, location?.path, location?.start_line, location?.end_line, context],
    queryFn: () =>
      fetchSource(scanId, { path: location?.path ?? "", line: location?.start_line, endLine: location?.end_line, context }),
    enabled: enabled && Boolean(location?.path),
    retry: false,
    staleTime: 60_000,
  });
}

function Legend({ marks }: { marks: SourceMark[] }) {
  const kinds = [...new Set(marks.map((mark) => mark.kind))];
  if (kinds.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1.5 text-[11px] text-ink-muted">
      {kinds.map((kind) => (
        <span key={kind} className={cn("rounded px-1.5 py-0.5 ring-1 ring-inset", MARK_TONE[kind])}>
          {MARK_NAME[kind]}
        </span>
      ))}
    </div>
  );
}

function CodeSheet({ scanId, finding, onClose }: { scanId: string; finding: Finding; onClose: () => void }) {
  const [whole, setWhole] = useState(false);
  const source = useSource(scanId, finding, whole ? 0 : 60);
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const view = source.data;
  const notes = (view?.marks ?? [])
    .filter((mark) => !(mark.kind === "finding" && mark.fingerprint === finding.fingerprint && mark.correlation_key === finding.correlation_key))
    .sort((left, right) => left.line - right.line);
  const jump = (line: number) => {
    const row = document.getElementById(`L${line}`);
    if (!row) return;
    row.scrollIntoView({ block: "center", behavior: "smooth" });
    row.animate([{ backgroundColor: "rgba(214,242,92,0.25)" }, { backgroundColor: "transparent" }], { duration: 1200 });
  };
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={onClose}>
      <div
        role="dialog"
        aria-label="Source code"
        className="flex h-full w-[min(1100px,100vw)] flex-col gap-3 border-l border-ink-line bg-ink-panel p-4 shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate font-mono text-xs text-ink-muted">
              {view?.path ?? finding.location?.path}:{finding.location?.start_line}
              {view && <span className="ml-2 opacity-70">{view.total_lines} lines</span>}
            </p>
            <h2 className="mt-1 text-sm font-medium leading-5 text-ink-text">{finding.title}</h2>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              onClick={() => setWhole((value) => !value)}
              className="h-8 rounded-md border border-ink-line px-3 text-xs text-ink-text hover:bg-white/5"
            >
              {whole ? "Around the finding" : "Whole file"}
            </button>
            <button type="button" onClick={onClose} aria-label="Close" className="grid size-8 place-items-center rounded-md border border-ink-line hover:bg-white/5">
              <X className="size-4" />
            </button>
          </div>
        </div>
        {view && <Legend marks={view.marks} />}
        <div className="grid min-h-0 flex-1 grid-rows-[minmax(0,1fr)_minmax(0,auto)] gap-3 lg:grid-cols-[minmax(0,1fr)_300px] lg:grid-rows-1">
          <div className="min-h-0 min-w-0">
            {source.isLoading && <p className="text-sm text-ink-muted">Loading source…</p>}
            {source.error && <p className="text-sm text-rose-200">{(source.error as Error).message}</p>}
            {view && <SourceLines view={view} finding={finding} compact={false} />}
          </div>
          <div className="max-h-48 min-h-0 min-w-0 space-y-2 overflow-auto text-xs lg:max-h-none">
            {finding.message && <p className="whitespace-pre-wrap break-words leading-5 text-ink-text/90">{finding.message}</p>}
            {notes.length > 0 && (
              <div className="space-y-1">
                <p className="font-medium text-ink-muted">In this file</p>
                {notes.map((mark, index) => (
                  <button
                    key={index}
                    type="button"
                    onClick={() => jump(mark.line)}
                    className="flex w-full items-start gap-2 rounded px-1 py-0.5 text-left hover:bg-white/5"
                  >
                    <span className="w-9 shrink-0 pt-0.5 text-right font-mono text-zinc-500">{mark.line}</span>
                    <MarkChip mark={mark} wrap />
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/** Source lines the finding points at, highlighted, with marks from the project map. */
export function FindingCode({ scanId, finding, fallback }: { scanId: string; finding: Finding; fallback?: ReactNode }) {
  const [open, setOpen] = useState(false);
  const source = useSource(scanId, finding, 8, Boolean(finding.location?.path));
  if (!finding.location?.path) return <>{fallback}</>;
  if (source.error) {
    return (
      <div className="space-y-1">
        {fallback}
        <p className="text-[11px] text-ink-muted">Source not shown: {(source.error as Error).message}</p>
      </div>
    );
  }
  const view = source.data;
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        {view ? <Legend marks={view.marks} /> : <span className="text-xs text-ink-muted">Loading source…</span>}
        <button
          type="button"
          onClick={() => setOpen(true)}
          disabled={!view}
          className="inline-flex h-7 shrink-0 items-center gap-1 rounded-md border border-ink-line px-2 text-xs text-ink-text hover:bg-white/5 disabled:opacity-40"
        >
          <Maximize2 className="size-3.5" /> Open code
        </button>
      </div>
      {view && <SourceLines view={view} finding={finding} compact />}
      {open && <CodeSheet scanId={scanId} finding={finding} onClose={() => setOpen(false)} />}
    </div>
  );
}
