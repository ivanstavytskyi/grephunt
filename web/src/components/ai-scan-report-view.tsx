import { Download, LoaderCircle, Send, X } from "lucide-react";
import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import type { Finding, ScanSummary } from "@/api/types";
import { AiMarkdownBody } from "@/components/ai-markdown-body";
import { parseReportSections } from "@/lib/ai-report-markdown";
import { readApiError, type SavedAiKey } from "@/lib/ai-storage";
import {
  buildScanExportMarkdown,
  downloadTextFile,
  scanExportFilename,
  type AiReportChatMessage,
} from "@/lib/scan-export";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export type { AiReportChatMessage };

function countBy<T>(items: T[], key: (item: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of items) {
    const k = key(item) || "unknown";
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

function severityTone(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-red-500/40 bg-red-500/10 text-red-200";
    case "high":
      return "border-orange-500/40 bg-orange-500/10 text-orange-100";
    case "medium":
      return "border-amber-500/40 bg-amber-500/10 text-amber-100";
    case "low":
      return "border-sky-500/40 bg-sky-500/10 text-sky-100";
    default:
      return "border-ink-line bg-ink-raised text-ink-muted";
  }
}

export function AiScanReportView({
  report,
  findings,
  scan,
  aiKey,
  onClose,
}: {
  report: string;
  findings: Finding[];
  scan: ScanSummary | undefined;
  aiKey: SavedAiKey;
  onClose: () => void;
}) {
  const { title, sections } = parseReportSections(report);
  const bySeverity = countBy(findings, (f) => f.severity);
  const byCategory = countBy(findings, (f) => f.category);
  const targetLabel = scan?.target_label;

  const [chatMessages, setChatMessages] = useState<AiReportChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState("");
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, chatLoading]);

  const sendChat = async () => {
    const question = chatInput.trim();
    if (!question || chatLoading) return;
    const nextMessages: AiReportChatMessage[] = [...chatMessages, { role: "user", content: question }];
    setChatInput("");
    setChatError("");
    setChatMessages(nextMessages);
    setChatLoading(true);
    try {
      const response = await fetch("/api/ai/scan-report/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          provider: aiKey.provider,
          api_key: aiKey.apiKey,
          model: aiKey.model,
          report,
          messages: nextMessages,
          findings,
          scan: {
            target_label: scan?.target_label,
            target_path: scan?.target_path,
            source_repo_url: scan?.source_repo_url,
            source_ref: scan?.source_ref,
            finding_count: findings.length,
            scanners: scan?.tasks?.map((task) => task.tool),
          },
        }),
      });
      const body = await response.json();
      if (!response.ok) {
        setChatError(typeof body.detail === "string" ? body.detail : await readApiError(response));
        setChatMessages((prev) => prev.slice(0, -1));
        setChatInput(question);
        return;
      }
      const answer = typeof body.text === "string" ? body.text.trim() : "";
      if (!answer) {
        setChatError("The model returned an empty answer.");
        setChatMessages((prev) => prev.slice(0, -1));
        setChatInput(question);
        return;
      }
      setChatMessages([...nextMessages, { role: "assistant", content: answer }]);
    } catch {
      setChatError("Could not reach the console");
      setChatMessages((prev) => prev.slice(0, -1));
      setChatInput(question);
    } finally {
      setChatLoading(false);
      inputRef.current?.focus();
    }
  };

  const onChatKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendChat();
    }
  };

  const saveExport = () => {
    if (!scan) return;
    const markdown = buildScanExportMarkdown({
      scan,
      findings,
      aiReport: report,
      chatMessages,
    });
    downloadTextFile(scanExportFilename(scan, "report"), markdown);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 p-4 pt-10 sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="ai-scan-report-title"
      onClick={onClose}
    >
      <div
        className="flex max-h-[min(92vh,920px)] w-full max-w-3xl flex-col overflow-hidden rounded-xl border border-ink-line bg-ink-panel shadow-2xl"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="flex shrink-0 items-start justify-between gap-4 border-b border-ink-line px-5 py-4">
          <div className="min-w-0">
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-signal">AI scan report</p>
            <h2 id="ai-scan-report-title" className="mt-1 text-lg font-semibold leading-snug tracking-tight text-ink-text">
              {title || targetLabel || "Security assessment"}
            </h2>
            <p className="mt-1 text-xs text-ink-muted">{findings.length} findings in this scan</p>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button
              type="button"
              aria-label="Export"
              title="Export markdown (AI summary, findings, and chat)"
              onClick={saveExport}
              className="flex size-9 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:bg-ink-raised hover:text-ink-text"
            >
              <Download className="size-4" aria-hidden="true" />
            </button>
            <button
              type="button"
              aria-label="Close report"
              onClick={onClose}
              className="flex size-9 items-center justify-center rounded-md border border-ink-line text-ink-muted hover:bg-ink-raised hover:text-ink-text"
            >
              <X className="size-4" aria-hidden="true" />
            </button>
          </div>
        </header>

        <div className="grid shrink-0 gap-3 border-b border-ink-line bg-ink-bg/40 px-5 py-4 sm:grid-cols-2">
          <div>
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-ink-muted">By severity</p>
            <div className="flex flex-wrap gap-1.5">
              {SEV_ORDER.filter((s) => (bySeverity[s] ?? 0) > 0).map((severity) => (
                <span
                  key={severity}
                  className={`rounded-md border px-2 py-0.5 font-mono text-[11px] capitalize ${severityTone(severity)}`}
                >
                  {severity} {bySeverity[severity]}
                </span>
              ))}
            </div>
          </div>
          <div>
            <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-ink-muted">By category</p>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(byCategory)
                .sort((a, b) => b[1] - a[1])
                .map(([category, count]) => (
                  <span
                    key={category}
                    className="rounded-md border border-ink-line bg-ink-raised px-2 py-0.5 font-mono text-[11px] capitalize text-ink-muted"
                  >
                    {category} {count}
                  </span>
                ))}
            </div>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {sections.length === 0 ? (
            <article className="rounded-lg border border-ink-line bg-ink-bg/30 p-4">
              <AiMarkdownBody markdown={report} />
            </article>
          ) : (
            <div className="space-y-3">
              {sections.map((section, index) => (
                <article
                  key={`${section.title}-${index}`}
                  className="rounded-lg border border-ink-line bg-ink-bg/30 p-4 shadow-sm shadow-black/20"
                >
                  {section.title && (
                    <h3 className="text-sm font-semibold tracking-tight text-ink-text">{section.title}</h3>
                  )}
                  <div className={section.title ? "mt-2" : ""}>
                    <AiMarkdownBody markdown={section.body} />
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        <section
          className="flex shrink-0 flex-col border-t border-ink-line bg-ink-bg/50"
          aria-label="Follow-up questions about this report"
        >
          <div className="border-b border-ink-line px-5 py-2">
            <p className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">Ask about this report</p>
          </div>
          <div className="max-h-52 min-h-[4.5rem] overflow-y-auto px-5 py-3">
            {chatMessages.length === 0 && !chatLoading && (
              <p className="text-xs leading-relaxed text-ink-muted">
                Example: «Which XSS findings are most likely exploitable?» or «Why is nanoid lower priority?»
              </p>
            )}
            <ul className="space-y-3">
              {chatMessages.map((message, index) => (
                <li
                  key={`${message.role}-${index}`}
                  className={message.role === "user" ? "flex justify-end" : "flex justify-start"}
                >
                  <div
                    className={
                      message.role === "user"
                        ? "max-w-[92%] rounded-lg border border-signal/30 bg-signal/10 px-3 py-2 text-sm text-ink-text"
                        : "max-w-[92%] rounded-lg border border-ink-line bg-ink-panel px-3 py-2 text-sm"
                    }
                  >
                    {message.role === "user" ? (
                      <p className="whitespace-pre-wrap leading-relaxed">{message.content}</p>
                    ) : (
                      <AiMarkdownBody markdown={message.content} />
                    )}
                  </div>
                </li>
              ))}
              {chatLoading && (
                <li className="flex justify-start">
                  <div className="flex items-center gap-2 rounded-lg border border-ink-line bg-ink-panel px-3 py-2 text-xs text-ink-muted">
                    <LoaderCircle className="size-3.5 animate-spin text-signal" aria-hidden="true" />
                    Thinking…
                  </div>
                </li>
              )}
            </ul>
            <div ref={chatEndRef} />
          </div>
          <div className="flex gap-2 border-t border-ink-line px-5 py-3">
            <textarea
              ref={inputRef}
              value={chatInput}
              onChange={(event) => setChatInput(event.target.value)}
              onKeyDown={onChatKeyDown}
              disabled={chatLoading}
              rows={2}
              placeholder="Follow-up question… (Enter to send, Shift+Enter for newline)"
              className="min-h-[2.75rem] flex-1 resize-none rounded-md border border-ink-line bg-ink-bg px-3 py-2 text-sm text-ink-text placeholder:text-ink-muted focus:border-signal/50 focus:outline-none disabled:opacity-50"
            />
            <button
              type="button"
              disabled={chatLoading || !chatInput.trim()}
              onClick={() => void sendChat()}
              aria-label="Send question"
              className="flex size-10 shrink-0 items-center justify-center self-end rounded-md border border-signal/60 text-signal hover:bg-signal/10 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {chatLoading ? (
                <LoaderCircle className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <Send className="size-4" aria-hidden="true" />
              )}
            </button>
          </div>
          {chatError && <p className="px-5 pb-3 text-xs text-red-300/90">{chatError}</p>}
        </section>
      </div>
    </div>
  );
}
