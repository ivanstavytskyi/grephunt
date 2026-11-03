import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import type { Components } from "react-markdown";

const components: Components = {
  p: ({ children }) => <p className="mt-2 first:mt-0 leading-6 text-ink-text/90">{children}</p>,
  strong: ({ children }) => <strong className="font-medium text-ink-text">{children}</strong>,
  em: ({ children }) => <em className="text-ink-muted">{children}</em>,
  ul: ({ children }) => <ul className="mt-2 list-disc space-y-1.5 pl-5 marker:text-ink-muted">{children}</ul>,
  ol: ({ children }) => (
    <ol className="mt-2 list-decimal space-y-2 pl-5 marker:font-mono marker:text-xs marker:text-signal/80">{children}</ol>
  ),
  li: ({ children }) => <li className="leading-6 text-ink-text/90">{children}</li>,
  h3: ({ children }) => (
    <h3 className="mt-4 first:mt-0 text-sm font-semibold tracking-tight text-ink-text">{children}</h3>
  ),
  h4: ({ children }) => <h4 className="mt-3 text-xs font-semibold uppercase tracking-wide text-ink-muted">{children}</h4>,
  code: ({ className, children }) => {
    const inline = !className;
    if (inline) {
      return (
        <code className="rounded bg-ink-raised px-1 py-0.5 font-mono text-[11px] text-signal/90">{children}</code>
      );
    }
    return (
      <code className="block overflow-x-auto rounded-md border border-ink-line bg-ink-bg p-3 font-mono text-[11px] leading-5">
        {children}
      </code>
    );
  },
  hr: () => <hr className="my-4 border-ink-line" />,
  a: ({ href, children }) => (
    <a href={href} className="text-signal underline-offset-2 hover:underline" target="_blank" rel="noreferrer">
      {children}
    </a>
  ),
};

export function AiMarkdownBody({ markdown }: { markdown: string }) {
  if (!markdown.trim()) return null;
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
      {markdown}
    </ReactMarkdown>
  );
}
