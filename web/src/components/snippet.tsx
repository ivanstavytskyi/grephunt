export function Snippet({ code }: { code: string; path: string | null }) {
  return (
    <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-5 text-ink-text">
      {code}
    </pre>
  );
}
