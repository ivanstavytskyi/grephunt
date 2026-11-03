/** Split model markdown into a title and ## sections for card layout. */
export type ReportSection = { title: string; body: string };

export function parseReportSections(raw: string): { title: string; sections: ReportSection[] } {
  const text = raw.trim();
  if (!text) return { title: "", sections: [] };

  let remainder = text;
  let title = "";
  const firstLine = text.split("\n")[0] ?? "";
  if (/^#\s+/.test(firstLine)) {
    title = firstLine.replace(/^#\s+/, "").replace(/`/g, "").trim();
    remainder = text.slice(firstLine.length).trim();
  }

  remainder = remainder.replace(/^---\s*\n+/m, "").trim();
  const chunks = remainder.split(/\n(?=##\s+)/).map((chunk) => chunk.trim()).filter(Boolean);

  const sections: ReportSection[] = [];
  for (const chunk of chunks) {
    const match = chunk.match(/^##\s+(.+?)(?:\n+([\s\S]*))?$/);
    if (match) {
      sections.push({
        title: cleanInline(match[1]),
        body: (match[2] ?? "").trim(),
      });
      continue;
    }
    if (sections.length === 0) {
      sections.push({ title: "Summary", body: chunk });
    } else {
      const last = sections[sections.length - 1];
      last.body = `${last.body}\n\n${chunk}`.trim();
    }
  }

  return { title, sections };
}

function cleanInline(value: string): string {
  return value.replace(/\*\*/g, "").replace(/`/g, "").trim();
}
